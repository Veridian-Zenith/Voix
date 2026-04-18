/**
 * @file security.cpp
 * @brief Enhanced security implementation
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "security.h"
#include "logger.h"
#include <unistd.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <pwd.h>
#include <vector>
#include <regex>
#include <algorithm>
#include <seccomp.h>
#include <memory>

namespace Voix {

struct CapDeleter {
    void operator()(cap_t p) const {
        if (p) cap_free(p);
    }
};
using UniqueCap = std::unique_ptr<std::remove_pointer_t<cap_t>, CapDeleter>;

struct SeccompDeleter {
    void operator()(scmp_filter_ctx ctx) const {
        if (ctx) seccomp_release(ctx);
    }
};
using UniqueSeccomp = std::unique_ptr<std::remove_pointer_t<scmp_filter_ctx>, SeccompDeleter>;

Security::Security() = default;

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
    struct passwd pwd;
    struct passwd* result = nullptr;
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;
    std::vector<char> buffer(static_cast<size_t>(bufsize));

    if (getpwnam_r(std::string(username).c_str(), &pwd, buffer.data(), buffer.size(), &result) != 0 || result == nullptr) {
        return false;
    }
    return true;
}

bool Security::isSafePath(std::string_view path) const {
    // Canonicalize path to prevent traversal bypasses
    try {
        std::filesystem::path p(path);
        // Use weakly_canonical to handle paths that may not exist yet
        std::filesystem::path canonical = std::filesystem::weakly_canonical(p);
        std::string canonical_str = canonical.string();

        // Check for path traversal attempts
        if (canonical_str.find("..") != std::string::npos) {
            return false;
        }

        // Check for absolute paths to sensitive locations
        static const std::vector<std::string_view> forbidden = {
            "/etc/shadow", "/etc/sudoers", "/root", "/etc/voix.conf"
        };

        for (auto target : forbidden) {
            if (canonical_str.find(target) != std::string::npos) return false;
        }

        return true;
    } catch (...) {
        return false;
    }
}

void Security::logEvent(std::string_view event, std::string_view user) const {
    std::ofstream log_file("/var/log/voix.log", std::ios::app);
    if (log_file.is_open()) {
        auto now = std::chrono::system_clock::now();
        log_file << std::format("{:%Y-%m-%d %H:%M:%S} [{}] {}\n", now, user, event);
        log_file.close();
    }
}

std::string Security::getCurrentUser() const {
    uid_t uid = getuid();
    struct passwd pwd;
    struct passwd* result = nullptr;
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;
    std::vector<char> buffer(static_cast<size_t>(bufsize));

    if (getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result) == 0 && result != nullptr) {
        return std::string(result->pw_name);
    }

    return "unknown";
}

bool Security::isCatastrophicCommand(std::string_view command, const std::vector<std::string>& args, const Config& config) const {
    std::string full_command = std::string(command);
    std::string normalized_command = std::string(command);

    for (const auto& arg : args) {
        full_command += " " + arg;

        // Attempt to normalize path arguments for better matching
        try {
            if (arg.starts_with("/") || arg.starts_with(".")) {
                normalized_command += " " + std::filesystem::absolute(arg).string();
            } else {
                normalized_command += " " + arg;
            }
        } catch (...) {
            normalized_command += " " + arg;
        }
    }

    // Trim
    auto trim = [](std::string& s) {
        s.erase(0, s.find_first_not_of(" \t\r\n"));
        s.erase(s.find_last_not_of(" \t\r\n") + 1);
    };
    trim(full_command);
    trim(normalized_command);

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

    // Regex check
    for (const auto& regex : config.get_compiled_blocklist()) {
        if (std::regex_search(full_command, regex) || std::regex_search(normalized_command, regex)) {
            return true;
        }
    }
    return false;
}

void Security::raiseCapabilities() {
    UniqueCap caps(cap_get_proc());
    if (!caps) {
        throw std::runtime_error("cap_get_proc failed");
    }

    cap_value_t required_caps[] = {CAP_AUDIT_WRITE, CAP_DAC_READ_SEARCH, CAP_SETUID};
    if (cap_set_flag(caps.get(), CAP_EFFECTIVE, 3, required_caps, CAP_SET) == -1) {
        throw std::runtime_error("cap_set_flag failed");
    }

    if (cap_set_proc(caps.get()) == -1) {
        throw std::runtime_error("Insufficient privileges. Voix must be installed setuid root or have proper file capabilities.");
    }
}

void Security::dropCapabilities(const std::vector<cap_value_t>& keep_caps) {
    UniqueCap caps(cap_get_proc());
    if (!caps) {
        LOG_WARN("Failed to get capabilities before dropping");
        return;
    }
    if(cap_clear(caps.get()) == -1) {
        LOG_WARN("Failed to clear capabilities");
        return;
    }
    if (!keep_caps.empty()) {
        if (cap_set_flag(caps.get(), CAP_PERMITTED, keep_caps.size(), keep_caps.data(), CAP_SET) == -1) {
            LOG_WARN("Failed to set permitted capabilities to keep");
        }
        if (cap_set_flag(caps.get(), CAP_EFFECTIVE, keep_caps.size(), keep_caps.data(), CAP_SET) == -1) {
            LOG_WARN("Failed to set effective capabilities to keep");
        }
    }
    if (cap_set_proc(caps.get()) == -1) {
        LOG_WARN("Failed to set capabilities (drop)");
    }
}

void Security::applySeccompBlacklist() const {
    UniqueSeccomp ctx(seccomp_init(SCMP_ACT_ALLOW));
    if (!ctx) {
        LOG_WARN("Failed to init seccomp");
        _exit(1);
    }

    if (seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, SCMP_SYS(kexec_load), 0) < 0 ||
        seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, SCMP_SYS(delete_module), 0) < 0 ||
        seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, SCMP_SYS(init_module), 0) < 0 ||
        seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, SCMP_SYS(finit_module), 0) < 0 ||
        seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, SCMP_SYS(reboot), 0) < 0 ||
        seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, SCMP_SYS(swapon), 0) < 0 ||
        seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, SCMP_SYS(swapoff), 0) < 0) {
        LOG_WARN("Failed to add seccomp rules");
        _exit(1);
    }

    if (seccomp_load(ctx.get()) < 0) {
        LOG_WARN("Failed to load seccomp");
        _exit(1);
    }
    LOG_WARN("Seccomp rules applied successfully");
}

} // namespace Voix
