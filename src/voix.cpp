/**
 * @file voix.cpp
 * @brief Enhanced Voix implementation with OpenDoas integration
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "voix.hpp"
#include "authenticator.hpp"
#include "permission_checker.hpp"
#include "command.hpp"
#include "security.hpp"
#include "config.hpp"
#include "logger.hpp"
#include "system_utils.hpp"
#include <syslog.h>
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

} // namespace

Voix::Voix(std::string_view config_path, bool non_interactive,
           bool clear_timestamp)
    : config_(std::make_shared<Config>()),
      security_(std::make_shared<Security>()),
      authenticator_(std::make_unique<PamAuthenticator>(security_, *config_, non_interactive)),
      permission_checker_(std::make_unique<PermissionChecker>(security_, config_)),
      command_(std::make_unique<Command>()) {

  if (!config_->load(config_path)) {
    throw std::runtime_error("Failed to load configuration");
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
  std::string command_str{command};
  std::string user_str{user};

  // Catastrophic command detection is safety-critical and always audited,
  // regardless of any nolog option.
  if (security_->isCatastrophicCommand(command_str, args, *config_)) {
    std::println(stderr, "voix: command blocked: catastrophic command forbidden.");
    security_->logEvent(std::format("Catastrophic command blocked: {}", command_str), current_user);
    syslog(LOG_AUTHPRIV | LOG_ALERT, "Catastrophic command blocked: %s", command_str.c_str());
    return 1;
  }

  // Validate target user identity
  auto pw_entry = lookup_passwd_by_name(user_str);
  if (!pw_entry || !security_->validateUser(user_str)) {
    syslog(LOG_AUTHPRIV | LOG_ERR, "Invalid target user: %s", user_str.c_str());
    return 1;
  }

  auto rule = permission_checker_->permit(command_str, args, pw_entry->uid);

  // The nolog option suppresses audit records containing the command text;
  // outcome summaries are still recorded so the audit trail shows that
  // something ran without revealing what.
  const bool nolog = rule && (rule->options & Rule::NOLOG);
  auto emit = [&](std::string_view event, int priority, bool always) {
      if (!nolog || always) {
          security_->logEvent(std::string(event), current_user);
          syslog(priority, "%s", Logger::sanitize_message(event).c_str());
      }
  };

  emit(std::format("Command execution requested: {}", command_str),
       LOG_AUTHPRIV | LOG_INFO, /*always=*/false);

  if (!rule) {
    std::println(stderr, "voix: command not permitted");
    emit("Command not permitted (command withheld: nolog)",
         LOG_AUTHPRIV | LOG_NOTICE, /*always=*/true);
    return 1;
  }

  if (!authenticator_->authenticate(rule, user_str)) {
    emit("Authentication failed", LOG_AUTHPRIV | LOG_NOTICE, /*always=*/true);
    return 1;
  }

  if (!authenticator_->openSession()) {
    std::println(stderr, "voix: failed to open session");
    emit("Failed to open PAM session", LOG_AUTHPRIV | LOG_ERR, /*always=*/true);
    return 1;
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
    syslog(LOG_AUTHPRIV | LOG_ERR, "Invalid target user: %s", user_str.c_str());
    return 1;
  }

  int res = command_->execute(command_str, args, *config_, merged_options, *rule, *target_identity);

  emit(std::format("Command executed (exit {}): {}", res, command_str),
       res == 0 ? LOG_AUTHPRIV | LOG_INFO : LOG_AUTHPRIV | LOG_NOTICE,
       /*always=*/false);
  if (nolog) {
    // Outcome-only summary keeps the audit trail honest without leaking the
    // command under nolog rules.
    security_->logEvent(std::format("Execution completed (exit {}), details withheld (nolog)", res),
                        current_user);
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
