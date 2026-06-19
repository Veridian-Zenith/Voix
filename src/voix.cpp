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

#include <security/pam_appl.h>
#include <termios.h>
#include <unistd.h>

#include <cstring>
#include <print>
#include <vector>
#include <format>
#include "pam_utils.hpp"

namespace Voix {

Voix::Voix(std::string_view config_path, bool non_interactive,
           bool clear_timestamp)
    : config_(std::make_shared<Config>()),
      security_(std::make_shared<Security>()),
      authenticator_(std::make_unique<PamAuthenticator>(security_, non_interactive)),
      permission_checker_(std::make_unique<PermissionChecker>(security_, config_)),
      command_(std::make_unique<Command>()),
      clear_timestamp_(clear_timestamp) {

  if (!config_->load(config_path)) {
    throw std::runtime_error("Failed to load configuration");
  }

  if (clear_timestamp_) {
    security_->logEvent("Timestamp cleared (persist authentication reset)",
                        "system");
  }

  ::Voix::Logger::suppress_stderr = config_->should_suppress_stderr();
}

Voix::~Voix() = default;

int Voix::execute(std::string_view command,
                  const std::vector<std::string> &args,
                  const CommandOptions& options,
                  std::string_view user) {

  std::string current_user = security_->getCurrentUser();

  // Security logging
  std::string command_str{command};
  std::string user_str{user};

  if (security_->isCatastrophicCommand(command_str, args, *config_)) {
    std::println(stderr, "voix: command blocked: this incantation is deemed catastrophic and is forbidden.");
    security_->logEvent(std::format("Catastrophic command blocked: {}", command_str), current_user);
    syslog(LOG_AUTHPRIV | LOG_ALERT, "Catastrophic command blocked: %s", command_str.c_str());
    return 1;
  }

  security_->logEvent(std::format("Command execution requested: {}", command_str), current_user);
  syslog(LOG_AUTHPRIV | LOG_INFO, "Command execution requested: %s as %s",
         command_str.c_str(), user_str.c_str());

  // Validate command using enhanced rules
  auto pw_entry = lookupPasswdByName(user_str);
  if (!pw_entry) {
    syslog(LOG_AUTHPRIV | LOG_ERR, "Invalid target user: %s", user_str.c_str());
    return 1;
  }
  uid_t target_uid = pw_entry->uid;

  auto rule = permission_checker_->permit(command_str, args, target_uid);

  if (!rule) {
    std::println(stderr, "voix: command not permitted");
    security_->logEvent(std::format("Command not permitted: {}", command_str), current_user);
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "Command not permitted: %s as %s",
           command_str.c_str(), user_str.c_str());
    return 1;
  }

  if (!authenticator_->authenticate(rule)) {
    security_->logEvent(std::format("Authentication failed for user: {}", current_user),
                        current_user);
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "Authentication failed for user: %s",
           current_user.c_str());
    return 1;
  }

  if (!authenticator_->openSession()) {
    std::println(stderr, "voix: failed to open session");
    security_->logEvent(std::format("Failed to open PAM session for command: {}", command_str),
                        current_user);
    syslog(LOG_AUTHPRIV | LOG_ERR, "Failed to open PAM session for user: %s",
           current_user.c_str());
    return 1;
  }

  CommandOptions merged_options = options;
  if (!merged_options.login_shell && config_->is_login_shell_default()) {
      merged_options.login_shell = true;
  }
  
  // Merge rule options into merged_options
  if (rule->options & Rule::KEEPENV) {
      merged_options.preserve_env = true;
  }
  
  int res = command_->execute(command_str, args, *config_, merged_options, user_str);
  authenticator_->closeSession();
  return res;
}

int Voix::listCommands() const {
    auto rules = permission_checker_->listPermittedRules();
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
        if (!opts.empty()) {
            entry += std::format(" [{}]", opts.substr(1));
        }
        std::println("  {}", entry);
    }
    return 0;
}

} // namespace Voix
