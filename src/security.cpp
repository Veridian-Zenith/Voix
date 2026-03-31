/**
 * @file security.cpp
 * @brief Enhanced security implementation
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "security.h"
#include <unistd.h>
#include <sys/types.h>
#include <chrono>
#include <format>
#include <fstream>
#include <iostream>
#include <pwd.h>
#include <vector>

namespace Voix {

Security::Security() = default;

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
    struct passwd pwd;
    struct passwd* result = nullptr;
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;
    std::vector<char> buffer(bufsize);

    if (getpwnam_r(username_str.c_str(), &pwd, buffer.data(), bufsize, &result) != 0 || result == nullptr) {
        return false;
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
    uid_t uid = getuid();
    struct passwd pwd;
    struct passwd* result = nullptr;
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;
    std::vector<char> buffer(bufsize);

    if (getpwuid_r(uid, &pwd, buffer.data(), bufsize, &result) == 0 && result != nullptr) {
        return std::string(result->pw_name);
    }

    return "unknown";
}

bool Security::isCatastrophicCommand(std::string_view command, const std::vector<std::string>& args) const {
    if (command == "rm" || command == "/bin/rm" || command == "/usr/bin/rm") {
        bool recursive = false;
        bool force = false;
        bool target_root = false;

        for (const auto& arg : args) {
            if (arg == "-r" || arg == "-R" || arg == "--recursive") recursive = true;
            else if (arg == "-f" || arg == "--force") force = true;
            else if (arg == "-rf" || arg == "-fr") { recursive = true; force = true; }
            else if (arg == "/" || arg == "/*") target_root = true;
        }

        if (recursive && force && target_root) {
            return true;
        }
    }
    return false;
}

} // namespace Voix
