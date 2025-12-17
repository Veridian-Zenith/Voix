/**
 * @file security.cpp
 * @brief Security and validation implementation
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include "security.h"
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>

namespace Voix {

Security::Security() = default;

Security::~Security() = default;

bool Security::validateUser(const std::string& username) const {
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
    struct passwd* pw = getpwnam(username.c_str());
    return pw != nullptr;
}

bool Security::validateCommand(const std::string& command,
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

bool Security::isSafePath(const std::string& path) const {
    // Check for path traversal attempts
    if (path.find("..") != std::string::npos) {
        return false;
    }

    // Check for absolute paths to sensitive locations
    if (path.find("/etc/shadow") != std::string::npos ||
        path.find("/etc/sudoers") != std::string::npos ||
        path.find("/root") != std::string::npos) {
        return false;
    }

    return true;
}

void Security::logEvent(const std::string& event, const std::string& user) const {
    std::ofstream log_file("/var/log/voix.log", std::ios::app);
    if (log_file.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        log_file << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S")
                << "." << std::setfill('0') << std::setw(3) << ms.count()
                << " [" << user << "] " << event << std::endl;
        log_file.close();
    }

    // Also log to syslog if available
    #ifdef __linux__
    // Note: This would require syslog.h in a real implementation
    #endif
}

std::string Security::getCurrentUser() const {
    uid_t uid = geteuid();
    struct passwd* pw = getpwuid(uid);

    if (pw) {
        return std::string(pw->pw_name);
    }

    return "unknown";
}

bool Security::isDangerousCommand(const std::string& command) const {
    // List of commands that should never be allowed
    static const std::vector<std::string> dangerous_commands = {
        "su", "sudo", "doas", "pkexec", "bash", "sh", "zsh", "fish",
        "dd", "mkfs", "fdisk", "parted", "rm", "rmdir", "chmod", "chown",
        "kill", "killall", "pkill", "systemctl", "service",
        "chroot", "unshare", "nsenter", "capsh"
    };

    for (const auto& dangerous : dangerous_commands) {
        if (command == dangerous) {
            return true;
        }
    }

    return false;
}

bool Security::containsShellMetacharacters(const std::string& str) const {
    const std::string dangerous_chars = "|&;$`(){}[]<>?!~*\\\"'";

    for (char c : str) {
        if (dangerous_chars.find(c) != std::string::npos) {
            return true;
        }
    }

    return false;
}

} // namespace Security
