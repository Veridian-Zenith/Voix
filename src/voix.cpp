/**
 * @file voix.cpp
 * @brief Main Voix class implementation
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include "voix.h"
#include "config.h"
#include "security.h"
#include "utils.h"
#include "pam_auth.h"
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

namespace Voix {

Voix::Voix(const std::string& config_path)
    : config_(std::make_unique<Config>())
    , security_(std::make_unique<Security>())
    , utils_(std::make_unique<Utils>())
    , pam_auth_(std::make_unique<PAMAuth>())
    , config_path_(config_path) {

    // Load configuration
    config_->load(config_path_);
}

Voix::~Voix() = default;

int Voix::execute(const std::string& command,
                  const std::vector<std::string>& args,
                  const std::optional<std::string>& user) {

    std::string current_user = security_->getCurrentUser();

    // Security logging
    security_->logEvent("Command execution requested: " + command, current_user);

    // First authenticate the user
    if (!authenticate()) {
        security_->logEvent("Authentication failed for user: " + current_user, current_user);
        return 1;
    }

    // Validate user permissions
    if (!security_->validateUser(current_user)) {
        security_->logEvent("Unauthorized user attempt: " + current_user, current_user);
        return 1;
    }

    // Validate command
    if (!validateCommand(command)) {
        security_->logEvent("Invalid command attempted: " + command, current_user);
        return 1;
    }

    // Execute the command
    return utils_->executeCommand(command, args, user);
}

bool Voix::isAllowed() const {
    std::string current_user = security_->getCurrentUser();

    // Check if user exists in system
    if (!pam_auth_->userExists(current_user)) {
        return false;
    }

    // Check configuration-based permissions first (primary method for Voix)
    if (pam_auth_->isAllowedInVoixConfig(current_user)) {
        return true;
    }

    // Fallback to traditional admin groups if no config rules exist
    if (pam_auth_->isInAdminGroup(current_user)) {
        return true;
    }

    // Also check Voix-specific admin groups
    if (pam_auth_->isInVoixAdminGroup(current_user)) {
        return true;
    }

    return false;
}

bool Voix::validateCommand(const std::string& command) const {
    std::string current_user = security_->getCurrentUser();

    // Get allowed commands for user
    auto allowed_commands = config_->getAllowedCommands(current_user);

    // If no specific commands are configured, check if user has sudo privileges
    if (allowed_commands.empty()) {
        return pam_auth_->hasSudoPrivilege(current_user);
    }

    // Check if user has access to all commands
    if (allowed_commands.size() == 1 && allowed_commands[0] == "*") {
        return true;
    }

    // Check specific command
    for (const auto& allowed_cmd : allowed_commands) {
        if (command == allowed_cmd) {
            return true;
        }
    }

    return false;
}

bool Voix::authenticate() const {
    std::string current_user = security_->getCurrentUser();
    return pam_auth_->authenticate(current_user);
}

} // namespace Voix
