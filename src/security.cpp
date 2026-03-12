/**
 * @file security.cpp
 * @brief Enhanced security implementation
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include "security.h"
#include <unistd.h>
#include <sys/types.h>
#include <chrono>
#include <format>
#include <fstream>
#include <iostream>
#include <pwd.h>

namespace Voix {

Security::Security()
    : dangerous_commands_({
        "su", "sudo", "doas", "pkexec", "bash", "sh", "zsh", "fish",
        "dd", "mkfs", "fdisk", "parted", "rm", "rmdir", "chmod", "chown",
        "kill", "killall", "pkill", "systemctl", "service",
        "chroot", "unshare", "nsenter", "capsh"
    }),
      dangerous_chars_("|&;$`(){}[]<>?!~*\\\"'") {}

Security::~Security() = default;

bool Security::validateUser(std::string_view username) const {
    // Basic validation - ensure username is not empty and contains only safe characters
    if (username.empty() || username.length() > 32) {
        return false;
    }

    for (char c : username) {
        if (!std::isalnum(c) && c != '_' && c != '-') {
            return false;
        }
    }

    // Check if user exists on the system
    std::string username_str{username};
    struct passwd* pw = getpwnam(username_str.c_str());
    return pw != nullptr;
}

bool Security::validateCommand(std::string_view command,
                             const std::vector<std::string>& args) const {

    // Check for dangerous commands
    if (isDangerousCommand(command)) {
        return false;
    }

    // Check for shell metacharacters in command and arguments
    if (containsShellMetacharacters(command)) {
        return false;
    }

    for (const auto& arg : args) {
        if (containsShellMetacharacters(arg)) {
            return false;
        }
    }

    return true;
}

bool Security::isSafePath(std::string_view path) const {
    // Check for path traversal attempts
    if (path.find("..") != std::string_view::npos) {
        return false;
    }

    // Check for absolute paths to sensitive locations
    if (path.find("/etc/shadow") != std::string_view::npos ||
        path.find("/etc/sudoers") != std::string_view::npos ||
        path.find("/root") != std::string_view::npos) {
        return false;
    }

    return true;
}

void Security::logEvent(std::string_view event, std::string_view user) const {
    std::ofstream log_file("/var/log/voix.log", std::ios::app);
    if (log_file.is_open()) {
        auto now = std::chrono::system_clock::now();
        log_file << std::format("{:%Y-%m-%d %H:%M:%S}", now)
                << " [" << user << "] " << event << '\n';
        log_file.close();
    }
}

std::string Security::getCurrentUser() const {
    uid_t uid = geteuid();
    struct passwd* pw = getpwuid(uid);

    if (pw) {
        return std::string(pw->pw_name);
    }

    return "unknown";
}

bool Security::isDangerousCommand(std::string_view command) const {
    for (const auto& dangerous : dangerous_commands_) {
        if (command == dangerous) {
            return true;
        }
    }
    return false;
}

bool Security::containsShellMetacharacters(std::string_view str) const {
    for (char c : str) {
        if (dangerous_chars_.find(c) != std::string::npos) {
            return true;
        }
    }
    return false;
}

} // namespace Voix
