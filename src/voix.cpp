/**
 * @file voix.cpp
 * @brief Enhanced Voix implementation with OpenDoas integration
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed
 * under OSL v3.
 */

#include "voix.h"
#include "authenticator.h"
#include "permission_checker.h"
#include "command.h"
#include "security.h"
#include "config.h"
#include <syslog.h>
#include <pwd.h>
#include <stdexcept>

#include <security/pam_appl.h>
#include <termios.h>
#include <unistd.h>
#include <iostream>
#include <cstring>
#include "pam_utils.h"

namespace Voix {

Voix::Voix(std::string_view config_path, bool non_interactive,
           bool clear_timestamp)
    : config_(std::make_shared<Config>()),
      security_(std::make_shared<Security>()),
      authenticator_(std::make_unique<Authenticator>(security_, non_interactive)),
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
}

Voix::~Voix() = default;

int Voix::execute(std::string_view command,
                  const std::vector<std::string> &args,
                  std::string_view user) {

  std::string current_user = security_->getCurrentUser();

  // Security logging
  std::string command_str{command};
  std::string user_str{user};
  security_->logEvent("Command execution requested: " + command_str, current_user);
  syslog(LOG_AUTHPRIV | LOG_INFO, "Command execution requested: %s as %s",
         command_str.c_str(), user_str.c_str());

  // Validate command using enhanced rules
  uid_t target_uid;
  struct passwd *pw = getpwnam(user_str.c_str());
  if (!pw) {
    syslog(LOG_AUTHPRIV | LOG_ERR, "Invalid target user: %s", user_str.c_str());
    return 1;
  }
  target_uid = pw->pw_uid;

  auto rule = permission_checker_->permit(command_str, args, target_uid);

  if (!rule) {
    security_->logEvent("Command not permitted: " + command_str, current_user);
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "Command not permitted: %s as %s",
           command_str.c_str(), user_str.c_str());
    return 1;
  }

  if (!authenticator_->authenticate(rule)) {
    security_->logEvent("Authentication failed for user: " + current_user,
                        current_user);
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "Authentication failed for user: %s",
           current_user.c_str());
    return 1;
  }

  return command_->execute(command_str, args, user_str);
}

} // namespace Voix
