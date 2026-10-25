/**
 * @file voix.cpp
 * @brief Enhanced Voix implementation with OpenDoas integration
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "voix.hpp"
#include "audit.hpp"
#include "authenticator.hpp"
#include "permission_checker.hpp"
#include "command.hpp"
#include "exit_code.hpp"
#include "file_utils.hpp"
#include "security.hpp"
#include "config.hpp"
#include "logger.hpp"
#include "system_utils.hpp"
#include <stdexcept>

#include <unistd.h>

#include <cstring>
#include <print>
#include <vector>
#include <format>
#include "pam_utils.hpp"

namespace Voix {

namespace {

/// RAII guard so a PAM session is never leaked, even on exceptions.
struct SessionCloser {
    IAuthenticator* auth;
    ~SessionCloser() {
        if (auth) auth->closeSession();
    }
};

ExitCode exit_code_for(FileError error) {
    switch (error) {
        case FileError::NotFound:
            return ExitCode::NotFound;
        case FileError::PermissionDenied:
            return ExitCode::NotPermitted;
        case FileError::ReadError:
        case FileError::WriteError:
        case FileError::Unknown:
            return ExitCode::NoExec;
    }
    return ExitCode::NoExec;
}

} // namespace

Voix::Voix(std::string_view config_path, bool non_interactive,
           bool clear_timestamp)
    : config_(std::make_shared<Config>()),
      security_(std::make_shared<Security>()),
      authenticator_(std::make_unique<PamAuthenticator>(security_, *config_, non_interactive)),
      permission_checker_(std::make_unique<PermissionChecker>(security_, config_)),
      command_(std::make_unique<Command>()) {

  if (!config_->load(config_path)) {
    throw VoixError(ExitCode::Config, config_->last_error(),
                    "check the file path and permissions; run "
                    "'voix --check-config -C <file>' for details");
  }

  if (clear_timestamp) {
    authenticator_->clear_timestamp();
  }

  ::Voix::Logger::suppress_stderr = config_->should_suppress_stderr();
}

Voix::~Voix() = default;

int Voix::execute(std::string_view command,
                  const std::vector<std::string> &args,
                  const CommandOptions& options,
                  std::string_view user) {

  std::string current_user = security_->getCurrentUser();
  std::string user_str{user};

  // Resolve the requested command before policy evaluation so ACL matching,
  // catastrophic-command detection, and execution all use the same canonical
  // root-owned executable. Absolute paths are no longer exempt.
  FileUtils file_utils;
  auto executable = file_utils.resolve_executable(command, config_->getPath());
  if (!executable) {
    const ExitCode code = exit_code_for(executable.error());
    std::string message;
    std::string hint;
    switch (executable.error()) {
      case FileError::NotFound:
        message = std::format("command not found: '{}'", command);
        hint = "check the command name, or core.paths in the configuration";
        break;
      case FileError::PermissionDenied:
        message = std::format(
            "refusing to run '{}': not a root-owned, non-writable executable",
            command);
        hint = "Voix only executes regular files owned by root without "
               "group/world write permission";
        break;
      case FileError::ReadError:
      case FileError::WriteError:
      case FileError::Unknown:
        message = std::format("cannot inspect executable: '{}'", command);
        hint = "check file permissions and that the command exists";
        break;
    }
    Logger().report_error(code, message, hint);
    security_->logEvent(
        Audit::command_rejected,
        std::format("{} [{}]", message, file_error_name(executable.error())),
        current_user);
    return exit_status(code);
  }
  const std::string command_str = executable->policy_path;

  // Catastrophic command detection is safety-critical and always audited,
  // regardless of any nolog option.
  if (security_->isCatastrophicCommand(command_str, args, *config_)) {
    const std::string message =
        std::format("blocked destructive command: '{}'", command_str);
    Logger().report_error(
        ExitCode::NotPermitted, message,
        "run destructive system operations from an already-root login shell; "
        "see docs/SUDO.md");
    security_->logEvent(Audit::command_blocked, message, current_user);
    return exit_status(ExitCode::NotPermitted);
  }

  // Validate target user identity
  auto pw_entry = lookup_passwd_by_name(user_str);
  if (!pw_entry || !security_->validateUser(user_str)) {
    const std::string message =
        std::format("unknown or invalid target user: '{}'", user_str);
    Logger().report_error(ExitCode::Usage, message,
                          "check the -u argument and that the account exists");
    security_->logEvent(Audit::invalid_target, message, current_user);
    return exit_status(ExitCode::Usage);
  }

  auto rule = permission_checker_->permit(command_str, args, pw_entry->uid);

  // The nolog option suppresses audit records containing the command text;
  // outcome summaries are still recorded so the audit trail shows that
  // something ran without revealing what.
  const bool nolog = rule && (rule->options & Rule::NOLOG);
  auto emit = [&](std::string_view code, std::string_view event, bool always) {
      if (!nolog || always) {
          security_->logEvent(code, event, current_user);
      }
  };

  emit(Audit::command_requested,
       std::format("command requested: {}", command_str), /*always=*/false);

  if (!rule) {
    Logger().report_error(
        ExitCode::NotPermitted,
        std::format("not permitted: '{}'", command_str),
        "run 'voix -l' to list permitted commands, or ask an administrator");
    emit(Audit::command_denied, "command not permitted", /*always=*/true);
    return exit_status(ExitCode::NotPermitted);
  }

  if (!authenticator_->authenticate(rule, user_str)) {
    std::string hint{authenticator_->last_error()};
    if (hint.empty()) {
      hint = "check your password and that your account is not locked";
    }
    Logger().report_error(ExitCode::Failure, "authentication failed", hint);
    emit(Audit::authentication_failed, "authentication failed",
         /*always=*/true);
    return exit_status(ExitCode::Failure);
  }

  if (!authenticator_->openSession()) {
    std::string hint{authenticator_->last_error()};
    if (hint.empty()) {
      hint = "check the PAM configuration and system logs";
    }
    Logger().report_error(ExitCode::Failure, "could not open session", hint);
    emit(Audit::session_open_failed, "failed to open PAM session",
         /*always=*/true);
    return exit_status(ExitCode::Failure);
  }

  SessionCloser closer{authenticator_.get()};

  CommandOptions merged_options = options;
  if (!merged_options.login_shell && config_->is_login_shell_default()) {
      merged_options.login_shell = true;
  }

  // Environment preservation requires an explicit keepenv policy grant; the
  // CLI -E flag alone cannot widen what the rule allows.
  merged_options.preserve_env = (rule->options & Rule::KEEPENV) != 0;

  // Resolve the full target identity once, in the parent, before fork().
  auto target_identity = security_->identity->get_user_by_name(user_str);
  if (!target_identity) {
    const std::string message =
        std::format("could not resolve target identity: '{}'", user_str);
    Logger().report_error(ExitCode::Software, message,
                          "check the system user database and PAM/NSS "
                          "configuration");
    emit(Audit::invalid_target, message, /*always=*/true);
    return exit_status(ExitCode::Software);
  }

  int res = command_->execute(*executable, args, *config_, merged_options,
                              *rule, *target_identity);

  emit(Audit::command_executed,
       std::format("command finished (exit {}): {}", res, command_str),
       /*always=*/false);
  if (nolog) {
    // Outcome-only summary keeps the audit trail honest without leaking the
    // command under nolog rules.
    emit(Audit::command_withheld,
         std::format("execution finished (exit {}), details withheld (nolog)",
                     res),
         /*always=*/true);
  }

  return res;
}

int Voix::list_commands() const {
    auto rules = permission_checker_->list_permitted_rules();
    if (rules.empty()) {
        std::println("No permitted commands for the current user.");
        return 0;
    }

    std::println("Permitted commands for user '{}':", security_->getCurrentUser());
    for (const auto& rule : rules) {
        std::string entry;
        if (rule.cmd.empty()) {
            entry = "(all commands)";
        } else {
            entry = rule.cmd;
            for (const auto& arg : rule.cmdargs) {
                entry += " " + arg;
            }
        }
        if (!rule.target.empty()) {
            entry += std::format(" as {}", rule.target);
        }
        std::string opts;
        if (rule.options & Rule::NOPASS) opts += " nopass";
        if (rule.options & Rule::KEEPENV) opts += " keepenv";
        if (rule.options & Rule::PERSIST) opts += " persist";
        if (rule.options & Rule::NOLOG) opts += " nolog";
        if (rule.options & Rule::PATTERN) opts += " pattern";
        if (!opts.empty()) {
            entry += std::format(" [{}]", opts.substr(1));
        }
        std::println("  {}", entry);
    }
    return 0;
}

} // namespace Voix
