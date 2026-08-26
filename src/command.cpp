/**
 * @file command.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "command.hpp"
#include "logger.hpp"
#include "file_utils.hpp"
#include "security.hpp"
#include "system_utils.hpp"
#include <csignal>
#include <pwd.h>
#include <grp.h>
#include <cerrno>
#include <cstring>

#include <format>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
#include <cstdlib>
#include <utility>
#include <filesystem>
#include <sys/resource.h>
#include <ranges>

namespace Voix {

SecurityProfile Command::resolve_profile(const Config& config, const Rule& rule,
                                       std::string_view target_user) {
    const bool target_unconfined = config.is_unconfined_target(target_user);

    SecurityProfile profile = config.get_profile(rule.profile);
    if (rule.profile.empty() && target_unconfined) {
        profile = SecurityProfile{/* retain_full_capabilities */ true,
                                  /* enable_seccomp         */ false,
                                  /* enable_resource_limits*/ false,
                                  /* scrub_environment     */ false,
                                  /* preserve_full_environment*/ true};
    }

    // Unconfined targets always keep their full environment, regardless of the
    // selected profile, because package managers and AUR helpers require it.
    if (target_unconfined) {
        profile.preserve_full_environment = true;
    }

    return profile;
}

int Command::execute(std::string_view command, const std::vector<std::string>& args,
                       const Config& config, const CommandOptions& options, const Rule& rule,
                       const UserIdentity& target) const {
  sigset_t new_mask, old_mask;
  sigfillset(&new_mask);
  if (pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask) != 0) {
      LOG_ERROR("Failed to block signals");
      return -1;
  }

  pid_t pid = fork();

  if (pid == -1) {
    LOG_ERROR(std::format("fork() failed: {}", std::strerror(errno)));
    pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
    return -1;
  } else if (pid == 0) {
    // Child process
    if (pthread_sigmask(SIG_SETMASK, &old_mask, nullptr) != 0) {
        LOG_ERROR("Child failed to restore signal mask");
        _exit(1);
    }

    // Reset all signal handlers to default and use a predictable umask so the
    // invoking user cannot influence file modes of privileged operations.
    for (int i = 1; i < NSIG; ++i) {
        signal(i, SIG_DFL);
    }
    umask(022);

    // Profile resolution order (see Command::resolve_profile):
    //   1. An explicit profile named on the rule (administrator's decision).
    //   2. The target is a configured unconfined system target (e.g. the
    //      package-manager user) -> full "system" treatment.
    //   3. Otherwise the safe restricted default.
    const std::string target_name = target.username.empty() ? "root" : target.username;
    SecurityProfile profile = resolve_profile(config, rule, target_name);
    const bool preserve_full_env = profile.preserve_full_environment;
    const bool preserve_sanitized_env = !preserve_full_env && options.preserve_env;
    const bool is_privileged_tier = profile.retain_full_capabilities;

    // Collect the environment to restore after clearenv(), based on the
    // requested policy. Unconfined targets keep the entire inherited
    // environment (required for package managers and AUR helpers); a granted
    // keepenv keeps everything except known dangerous loader / interpreter
    // variables; otherwise only a minimal safe whitelist is kept.
    const std::vector<std::string> whitelist = {"TERM", "DISPLAY", "XAUTHORITY", "LANG", "PATH"};
    const std::array<std::string_view, 7> dangerous_env_names = {
        "BASH_ENV", "ENV", "IFS", "CDPATH",
        "GCONV_PATH", "GETCONF_DIR", "HOSTALIASES"
    };
    const std::array<std::string_view, 7> dangerous_env_prefixes = {
        "LD_", "CC", "CXX", "CMAKE_", "PERL", "PYTHON", "RUBY"
    };

    auto collect_environment = [&](bool keep_all, bool keep_sanitized) {
        std::vector<std::pair<std::string, std::string>> env;
        extern char **environ;
        for (char **e = ::environ; *e != nullptr; ++e) {
            std::string entry(*e);
            const size_t pos = entry.find('=');
            if (pos == std::string::npos) continue;
            std::string key = entry.substr(0, pos);
            if (!keep_all) {
                const bool is_dangerous_name =
                    std::ranges::find(dangerous_env_names, std::string_view{key}) != dangerous_env_names.end();
                const bool is_dangerous_prefix =
                    std::ranges::any_of(dangerous_env_prefixes, [&](std::string_view prefix) {
                        return key.starts_with(prefix);
                    });
                if (keep_sanitized && (is_dangerous_name || is_dangerous_prefix)) continue;
                if (!keep_sanitized && std::ranges::find(whitelist, key) == whitelist.end()) continue;
            }
            env.emplace_back(key, entry.substr(pos + 1));
        }
        return env;
    };

    std::vector<std::pair<std::string, std::string>> saved_env;
    if (preserve_full_env) {
        saved_env = collect_environment(/* keep_all */ true, /* keep_sanitized */ false);
    } else if (preserve_sanitized_env) {
        saved_env = collect_environment(/* keep_all */ false, /* keep_sanitized */ true);
    } else {
        saved_env = collect_environment(/* keep_all */ false, /* keep_sanitized */ false);
    }

    // Drop privileges completely. Supplementary groups were resolved in the
    // parent before fork() — no name-service activity happens here.
    if (!target.groups.empty()) {
        if (setgroups(target.groups.size(), target.groups.data()) != 0) {
            LOG_ERROR(std::format("setgroups() failed for '{}': {}", target.username, std::strerror(errno)));
            _exit(1);
        }
    }
    if (setgid(target.gid) != 0) {
        LOG_ERROR(std::format("setgid({}) failed: {}", target.gid, std::strerror(errno)));
        _exit(1);
    }
    if (setuid(target.uid) != 0) {
        LOG_ERROR(std::format("setuid({}) failed: {}", target.uid, std::strerror(errno)));
        _exit(1);
    }

    Security sec;

    // Drop capabilities for targets not in a full-privilege profile.
    #ifdef VOIX_WITH_CAP
    if (!is_privileged_tier) {
        sec.dropCapabilities({});
    }
    // Privileged tier: capabilities are intentionally retained (package
    // managers need CAP_CHOWN etc.). Nothing is dropped here.
    #endif

    // Scrub environment to maintain security.
    clearenv();
    // Restore only approved/sanitized environment variables
    std::ranges::for_each(saved_env, [](const auto& env) {
      setenv(env.first.c_str(), env.second.c_str(), 1);
    });

    // In restricted mode PATH is overridden with the trusted configured
    // directories; keepenv/unconfined tiers deliberately inherit the caller's
    // PATH as part of their policy grant.
    if (!preserve_full_env && !preserve_sanitized_env) {
      setenv("PATH", config.getPath().c_str(), 1);
    }
    setenv("USER", target.username.c_str(), 1);
    setenv("LOGNAME", target.username.c_str(), 1);
    setenv("HOME", target.home_dir.c_str(), 1);

    // Set shell
    if (options.login_shell) {
      setenv("SHELL", target.shell.c_str(), 1);
    }

    // Apply administrator-specified rule environment (KEY=VALUE entries from
    // the config's `env` list). These are root-defined and applied after
    // sanitization.
    SystemUtils sys_utils;
    sys_utils.setEnvironment(rule.envlist);

    // Capture the original FD limit before any reduction, so the close loop
    // covers all inherited descriptors.
    struct rlimit original_rl;
    bool have_original_rl = (getrlimit(RLIMIT_NOFILE, &original_rl) == 0);

    // Apply resource limits only to non-privileged targets. Privileged targets
    // may need high NPROC (pacman hooks spawn many processes) and NOFILE limits.
    if (profile.enable_resource_limits) {
        setResourceLimits();  // Fatal on failure — never fail open.
    }

// Close inherited FDs for all non-privileged executions (prevents voix
// internal FD leakage into the executed command). Privileged targets may
// rely on inherited FDs (e.g. D-Bus sockets for pacman hooks).
if (!is_privileged_tier) {
    bool closed = false;
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3, ~0U, 0) == 0) {
        closed = true;
    }
#endif

    if (!closed) {
        constexpr rlim_t k_fallback_max_fd = 4096;
        constexpr rlim_t k_close_loop_cap = 65536;
        rlim_t max_fd_limit = k_fallback_max_fd;
        if (have_original_rl) {
            max_fd_limit = std::min(original_rl.rlim_cur, k_close_loop_cap);
        }
        int max_fd = static_cast<int>(max_fd_limit);
        for (int i : std::views::iota(3, max_fd)) {
            close(i);
        }
    }
}

    auto escape = [](const std::string& s) {
      std::string escaped = "'";
      for (char c : s) {
        if (c == '\'') escaped += "'\\''";
        else escaped += c;
      }
      escaped += "'";
      return escaped;
    };

    std::vector<const char *> argv;
    std::string cmd_str{command};
    // Honor the rule's nolog option: never write the command text to the
    // audit log when suppression is requested.
    if (!(rule.options & Rule::NOLOG)) {
        LOG_INFO(std::format("executing command: {}, profile: {}", cmd_str, rule.profile));
    }

    // Resolve non-absolute paths
    if (!cmd_str.empty() && cmd_str[0] != '/') {
        FileUtils file_utils;
        std::string resolved = file_utils.resolve_command({cmd_str, config.getPath()});
        if (resolved.empty()) {
            LOG_ERROR(std::format("Command not found: {}", cmd_str));
            _exit(127);
        }
        cmd_str = resolved;
    }

    // Enforce absolute paths
    if (cmd_str.empty() || cmd_str[0] != '/') {
        LOG_ERROR(std::format("Command must be an absolute path: {}", cmd_str));
        _exit(127);
    }

    argv.push_back(cmd_str.c_str());
    for (const auto &arg : args) {
      argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    // PR_SET_NO_NEW_PRIVS is unconditional for non-privileged targets:
    // executed setuid binaries must not regain privileges. The seccomp
    // filter is an additional layer controlled by the profile/config.
    if (!is_privileged_tier) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            LOG_ERROR("Failed to set PR_SET_NO_NEW_PRIVS");
            _exit(1);
        }
#ifdef VOIX_WITH_SECCOMP
        if (config.is_seccomp_enabled() && profile.enable_seccomp) {
            sec.applySeccompBlacklist();
        }
#endif
    }

    if (options.login_shell) {
      // Execute command in a login shell. Login mode uses the POSIX argv[0]
      // leading-dash convention ("-bash"), which every shell understands,
      // instead of the "-l" option that dash/sh reject.
      std::string login_argv0 = "-" +
          std::filesystem::path(target.shell).filename().string();
      std::string c_arg = "-c";
      std::string full_cmd = escape(cmd_str);
      for (const auto &arg : args) {
        full_cmd += " " + escape(arg);
      }

      const char *args_exec[] = {login_argv0.c_str(), c_arg.c_str(), full_cmd.c_str(), nullptr};
      execv(target.shell.c_str(), const_cast<char *const *>(args_exec));
    } else {
      execv(cmd_str.c_str(), const_cast<char *const *>(argv.data()));
    }
    _exit(127);
  } else {
    // Parent process
    int status;
    waitpid(pid, &status, 0);

    if (pthread_sigmask(SIG_SETMASK, &old_mask, nullptr) != 0) {
        LOG_ERROR("Parent failed to restore signal mask");
        // Non-fatal, continue
    }

    if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    }
    return -1;
  }
}

void Command::setResourceLimits() const {
    struct rlimit rl;

    // Limit open file descriptors
    rl.rlim_cur = 1024;
    rl.rlim_max = 4096;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        LOG_ERROR(std::format("Failed to set RLIMIT_NOFILE: {}", std::strerror(errno)));
        _exit(1);
    }

    // Limit number of processes to prevent fork bombs
    rl.rlim_cur = 512;
    rl.rlim_max = 1024;
    if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
        LOG_ERROR(std::format("Failed to set RLIMIT_NPROC: {}", std::strerror(errno)));
        _exit(1);
    }

    // Limit core dump size (prevent sensitive memory from being written to disk)
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rl) != 0) {
        LOG_ERROR(std::format("Failed to set RLIMIT_CORE: {}", std::strerror(errno)));
        _exit(1);
    }
}

} // namespace Voix
