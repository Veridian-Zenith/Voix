/**
 * @file command.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "command.h"
#include "logger.h"
#include <csignal>
#include <pwd.h>
#include <grp.h>

#include <format>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>
#include <cstdlib>
#include <utility>
#include <sys/resource.h>

namespace Voix {

int Command::execute(std::string_view command, const std::vector<std::string>& args,
                      const Config& config, const CommandOptions& options, std::string_view user) const {
  sigset_t new_mask, old_mask;
  sigfillset(&new_mask);
  if (pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask) != 0) {
      LOG_ERROR("Failed to block signals");
      return -1;
  }

  pid_t pid = fork();

  if (pid == -1) {
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

    std::string user_str{user};
    struct passwd pwd;
    struct passwd *pw = nullptr;
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;
    std::vector<char> buffer(bufsize);

    if (getpwnam_r(user.empty() ? "root" : user_str.c_str(), &pwd, buffer.data(), bufsize, &pw) != 0 || !pw) {
      _exit(1);
    }

    // Preserve whitelist environment
    std::vector<std::string> whitelist = {"TERM", "DISPLAY", "XAUTHORITY", "LANG", "PATH", "CMAKE_PREFIX_PATH", "CMAKE_INCLUDE_PATH", "CC", "CXX"};
    std::vector<std::pair<std::string, std::string>> saved_env;
    if (options.preserve_env) {
      extern char **environ;
      for (char **env = ::environ; *env != nullptr; ++env) {
        std::string entry(*env);
        size_t pos = entry.find('=');
        if (pos != std::string::npos) {
          saved_env.push_back({entry.substr(0, pos), entry.substr(pos + 1)});
        }
      }
    } else {
      for (const auto& var : whitelist) {
        if (const char* val = getenv(var.c_str())) {
          saved_env.push_back({var, val});
        }
      }
    }

    // Drop privileges completely
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) _exit(1);
    if (setgid(pw->pw_gid) != 0) _exit(1);
    if (setuid(pw->pw_uid) != 0) _exit(1);

    // Scrub the environment
    clearenv();

    // Restore whitelist & explicitly set target identity
    for (const auto& env : saved_env) {
      setenv(env.first.c_str(), env.second.c_str(), 1);
    }
    setenv("PATH", config.getPath().c_str(), 1);
    setenv("USER", pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);
    setenv("HOME", pw->pw_dir, 1);

    // Set shell
    if (options.login_shell) {
      setenv("SHELL", pw->pw_shell, 1);
    }

    // Prevent FD leakage
    setResourceLimits();
    bool closed = false;
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3, ~0U, 0) == 0) {
      closed = true;
    }
#endif

    if (!closed) {
      struct rlimit rl;
      if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
          rl.rlim_cur = 4096; // Fallback
      }
      int max_fd = static_cast<int>(rl.rlim_cur);
      for (int i = 3; i < max_fd; ++i) {
        close(i);
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
    argv.push_back(cmd_str.c_str());
    for (const auto &arg : args) {
      argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    // Enforce absolute paths
    if (cmd_str.empty() || cmd_str[0] != '/') {
        LOG_ERROR("Command must be an absolute path: {}", cmd_str);
        _exit(127);
    }

    if (options.login_shell) {
      // Execute command in a login shell
      std::string login_shell_cmd = "-l";
      std::string c_arg = "-c";
      std::string full_cmd = escape(cmd_str);
      for (const auto &arg : args) {
        full_cmd += " " + escape(arg);
      }

      const char *args_exec[] = {pw->pw_shell, login_shell_cmd.c_str(), c_arg.c_str(), full_cmd.c_str(), nullptr};
      execv(pw->pw_shell, const_cast<char *const *>(args_exec));
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
    // Set reasonable default limits
    rl.rlim_cur = 1024; // Lower soft limit
    rl.rlim_max = 4096; // Hard limit

    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
        LOG_ERROR("Failed to set RLIMIT_NOFILE");
    }
}

std::string Command::buildCommandString(std::string_view command,
                                        const std::vector<std::string>& args,
                                        std::string_view user) const {
  std::string result;
  if (!user.empty() && user != "root") {
    result = std::format("su - {} -c {}", user, command);
  } else {
    result = command;
  }
  for (const auto& arg : args) {
    result += std::format(" {}", arg);
  }
  return result;
}

} // namespace Voix
