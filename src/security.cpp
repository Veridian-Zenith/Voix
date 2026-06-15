/**
 * @file security.cpp
 * @brief Enhanced security implementation
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "security.hpp"
#include "logger.hpp"
#include <unistd.h>
#ifdef VOIX_WITH_CAP
#include <sys/capability.h>
#endif
#include <sys/types.h>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <pwd.h>
#include <vector>
#include <regex>
#include <algorithm>
#ifdef VOIX_WITH_SECCOMP
#include <seccomp.h>
#endif
#include <memory>

namespace Voix {

#ifdef VOIX_WITH_CAP
struct CapDeleter {
    void operator()(cap_t p) const {
        if (p) cap_free(p);
    }
};
using UniqueCap = std::unique_ptr<std::remove_pointer_t<cap_t>, CapDeleter>;
#endif

#ifdef VOIX_WITH_SECCOMP
struct SeccompDeleter {
    void operator()(scmp_filter_ctx ctx) const {
        if (ctx) seccomp_release(ctx);
    }
};
using UniqueSeccomp = std::unique_ptr<std::remove_pointer_t<scmp_filter_ctx>, SeccompDeleter>;
#endif

Security::Security(std::shared_ptr<IIdentity> identity)
    : identity(std::move(identity)) {}

bool Security::validateUser(std::string_view username) const {
    if (username.empty() || username.length() > 32) {
        return false;
    }

    for (char c : username) {
        if (!std::isalnum(c) && c != '_' && c != '-') {
            return false;
        }
    }

    return identity->get_user_by_name(std::string(username)).has_value();
}

bool Security::isSafePath(std::string_view path) const {
    // Canonicalize path to prevent traversal bypasses
    try {
        std::filesystem::path p(path);
        
        // Check for path traversal attempts before canonicalization
        for (const auto& part : p) {
            if (part == "..") {
                return false;
            }
        }
        
        // Use weakly_canonical to handle paths that may not exist yet
        std::filesystem::path canonical = std::filesystem::weakly_canonical(p);
        
        // Check for absolute paths to sensitive locations
        static const std::vector<std::string_view> forbidden = {
            "/etc/shadow", "/etc/sudoers", "/root", "/etc/voix.conf"
        };
        
        const auto is_same_or_descendant = [](const std::filesystem::path& candidate,
                                           const std::filesystem::path& base) -> bool {
            auto c_it = candidate.begin();
            auto b_it = base.begin();
            for (; b_it != base.end(); ++b_it, ++c_it) {
                if (c_it == candidate.end() || *c_it != *b_it) {
                    return false;
                }
            }
            return true; // same path or candidate is within base
        };
        
        for (auto target : forbidden) {
            std::filesystem::path forbidden_path = std::filesystem::weakly_canonical(std::filesystem::path(target));
            if (is_same_or_descendant(canonical, forbidden_path)) return false;
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
    return identity->get_current_username();
}

uid_t Security::get_current_uid() const {
    return identity->get_current_uid();
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

    // Check for explicit blocked commands first (faster)
    for (const auto& forbidden_cmd : config.get_blocklist()) {
        if (command == forbidden_cmd) return true;
    }

    // Regex check (slower)
    for (const auto& regex : config.get_compiled_blocklist()) {
        if (std::regex_search(full_command, regex) || std::regex_search(normalized_command, regex)) {
            return true;
        }
    }
    return false;
}

#ifdef VOIX_WITH_CAP
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
        LOG_ERROR("Failed to get capabilities before dropping");
        _exit(1);
    }
    if(cap_clear(caps.get()) == -1) {
        LOG_ERROR("Failed to clear capabilities");
        _exit(1);
    }
    if (!keep_caps.empty()) {
        if (cap_set_flag(caps.get(), CAP_PERMITTED, keep_caps.size(), keep_caps.data(), CAP_SET) == -1) {
            LOG_ERROR("Failed to set permitted capabilities to keep");
            _exit(1);
        }
        if (cap_set_flag(caps.get(), CAP_EFFECTIVE, keep_caps.size(), keep_caps.data(), CAP_SET) == -1) {
            LOG_ERROR("Failed to set effective capabilities to keep");
            _exit(1);
        }
    }
    if (cap_set_proc(caps.get()) == -1) {
        LOG_ERROR("Failed to set capabilities (drop)");
        _exit(1);
    }
}
#endif

#ifdef VOIX_WITH_SECCOMP
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
        seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, SCMP_SYS(swapoff), 0) < 0 ||
        seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, SCMP_SYS(ptrace), 0) < 0 ||
        seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, SCMP_SYS(bpf), 0) < 0) {
        LOG_WARN("Failed to add seccomp rules");
        _exit(1);
    }

    if (seccomp_load(ctx.get()) < 0) {
        LOG_ERROR("Failed to load seccomp");
        _exit(1);
    }
}
#endif

} // namespace Voix
