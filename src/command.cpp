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
#include <unistd.h>
#include <vector>
#include <cstdlib>
#include <utility>
#include <sys/resource.h>
#include <ranges>

namespace Voix {

int Command::execute(std::string_view command, const std::vector<std::string>& args,
                       const Config& config, const CommandOptions& options, const Rule& rule, std::string_view user) const {
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

    // Reset all signal handlers to default
    for (int i = 1; i < NSIG; ++i) {
        signal(i, SIG_DFL);
    }

    // Resolve identity and profile
    auto pw_entry = Voix::lookupPasswdByName(user.empty() ? "root" : user);
    if (!pw_entry) {
      LOG_ERROR(std::format("Failed to resolve target user '{}': {}",
               user.empty() ? std::string_view{"root"} : user, std::strerror(errno)));
      _exit(1);
    }

    SecurityProfile profile = config.getProfile(rule.profile);
    bool is_privileged_user = (pw_entry->uid == 0 || config.isPrivilegedUser(user));
    // When no explicit profile is set, fall back to the privileged heuristic
    if (rule.profile.empty() && is_privileged_user) {
        profile = SecurityProfile{true, false, false, false};
    }
    bool is_privileged_tier = profile.retain_full_capabilities;

    const std::vector<std::string> whitelist = {"TERM", "DISPLAY", "XAUTHORITY", "LANG", "PATH"};
    const std::array<std::string_view, 7> dangerous_env_names = {
        "BASH_ENV", "ENV", "IFS", "CDPATH",
        "GCONV_PATH", "GETCONF_DIR", "HOSTALIASES"
    };
    const std::array<std::string_view, 7> dangerous_env_prefixes = {
        "LD_", "CC", "CXX", "CMAKE_", "PERL", "PYTHON", "RUBY"
    };
    std::vector<std::pair<std::string, std::string>> saved_env;
    
    if (options.preserve_env || is_privileged_user) {
      extern char **environ;
      for (char **env = ::environ; *env != nullptr; ++env) {
        std::string entry(*env);
        size_t pos = entry.find('=');
        if (pos != std::string::npos) {
          std::string key = entry.substr(0, pos);
          // Sanitize sensitive environment variables
          const bool is_dangerous_name =
              std::ranges::find(dangerous_env_names, std::string_view{key}) != dangerous_env_names.end();
          const bool is_dangerous_prefix =
              std::ranges::any_of(dangerous_env_prefixes, [&](std::string_view prefix) {
                return key.starts_with(prefix);
              });
          if (is_dangerous_name || is_dangerous_prefix) continue;
          saved_env.push_back({key, entry.substr(pos + 1)});
        }
      }
    } else {
      std::ranges::for_each(whitelist, [&](const auto& var) {
        if (const char* val = getenv(var.c_str())) {
          saved_env.push_back({var, val});
        }
      });
    }

    // Drop privileges completely
    if (initgroups(pw_entry->name.c_str(), pw_entry->gid) != 0) {
        LOG_ERROR(std::format("initgroups() failed for '{}': {}", pw_entry->name, std::strerror(errno)));
        _exit(1);
    }
    if (setgid(pw_entry->gid) != 0) {
        LOG_ERROR(std::format("setgid({}) failed: {}", pw_entry->gid, std::strerror(errno)));
        _exit(1);
    }
    if (setuid(pw_entry->uid) != 0) {
        LOG_ERROR(std::format("setuid({}) failed: {}", pw_entry->uid, std::strerror(errno)));
        _exit(1);
    }

    Security sec;

    // Drop capabilities for targets not in a full-privilege profile.
    #ifdef VOIX_WITH_CAP
    if (!is_privileged_tier) {
        sec.dropCapabilities({});
    } else {
        // Explicitly retain all capabilities for privileged targets
        // by NOT dropping them, and ensuring they are not restricted
        // by further security measures.
    }
    #endif


    // Scrub environment to maintain security.
    // Privileged users need a full environment to perform hooks and system
    // operations without breaking D-Bus or other services, but we still clear
    // the environment and restore only the sanitized variables to prevent privilege escalation.
    clearenv();
    // Restore only approved/sanitized environment variables
    std::ranges::for_each(saved_env, [](const auto& env) {
      setenv(env.first.c_str(), env.second.c_str(), 1);
    });

    setenv("PATH", config.getPath().c_str(), 1);
    setenv("USER", pw_entry->name.c_str(), 1);
    setenv("LOGNAME", pw_entry->name.c_str(), 1);
    setenv("HOME", pw_entry->home_dir.c_str(), 1);

    // Set shell
    if (options.login_shell) {
      setenv("SHELL", pw_entry->shell.c_str(), 1);
    }

    // Capture the original FD limit before any reduction, so the close loop
    // covers all inherited descriptors.
    struct rlimit original_rl;
    bool have_original_rl = (getrlimit(RLIMIT_NOFILE, &original_rl) == 0);

    // Apply resource limits only to non-privileged targets. Privileged targets
    // may need high NPROC (pacman hooks spawn many processes) and NOFILE limits.
    // Privileged targets also need unrestricted access to /proc/pid/root (snap-pac, etc.)
    // which requires full capabilities and bypassing seccomp.
    if (profile.enable_resource_limits) {
        setResourceLimits();
    }

    // Close inherited FDs only for non-privileged executions (prevents voix internal FD leakage)
    // Privileged targets (pacman hooks) may rely on inherited FDs like D-Bus sockets.
    bool closed = false;
    if (profile.scrub_environment) {
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
    LOG_ERROR(std::format("executing command: {}, profile: {}", cmd_str, rule.profile));

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

    // Apply seccomp only to targets with seccomp enabled in their profile. Privileged targets
    // need unrestricted syscall access.
    if (config.is_seccomp_enabled() && profile.enable_seccomp) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            LOG_ERROR("Failed to set PR_SET_NO_NEW_PRIVS");
            _exit(1);
        }
#ifdef VOIX_WITH_SECCOMP
        sec.applySeccompBlacklist();
#endif
    }

    if (options.login_shell) {
      // Execute command in a login shell
      std::string login_shell_cmd = "-l";
      std::string c_arg = "-c";
      std::string full_cmd = escape(cmd_str);
      for (const auto &arg : args) {
        full_cmd += " " + escape(arg);
      }

      const char *args_exec[] = {pw_entry->shell.c_str(), login_shell_cmd.c_str(), c_arg.c_str(), full_cmd.c_str(), nullptr};
      execv(pw_entry->shell.c_str(), const_cast<char *const *>(args_exec));
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
        LOG_ERROR("Failed to set RLIMIT_NOFILE");
    }

    // Limit number of processes to prevent fork bombs
    rl.rlim_cur = 512;
    rl.rlim_max = 1024;
    if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
        LOG_ERROR("Failed to set RLIMIT_NPROC");
    }

    // Limit core dump size (prevent sensitive memory from being written to disk)
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rl) != 0) {
        LOG_ERROR("Failed to set RLIMIT_CORE");
    }
}

std::string Command::buildCommandString(std::string_view command,
                                        const std::vector<std::string>& args,
                                        std::string_view user) const {
  auto shell_escape = [](std::string_view s) -> std::string {
    std::string escaped = "'";
    for (char c : s) {
      if (c == '\'') escaped += "'\\''";
      else escaped += c;
    }
    escaped += "'";
    return escaped;
  };

  std::string result;
  if (!user.empty() && user != "root") {
    result = std::format("su - {} -c {}", shell_escape(user), shell_escape(command));
  } else {
    result = shell_escape(command);
  }
  for (const auto& arg : args) {
    result += std::format(" {}", shell_escape(arg));
  }
  return result;
}

} // namespace Voix
