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
    std::vector<std::string> whitelist = {"TERM", "DISPLAY", "XAUTHORITY", "LANG", "PATH", "LD_LIBRARY_PATH", "CMAKE_PREFIX_PATH", "CMAKE_INCLUDE_PATH", "CC", "CXX"};
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
      long max_fd_l = sysconf(_SC_OPEN_MAX);
      if (max_fd_l < 0 || max_fd_l > 4096) max_fd_l = 4096;
      int max_fd = static_cast<int>(max_fd_l);
      for (int i = 3; i < max_fd; ++i) {
        close(i);
      }
    }

    std::vector<const char *> argv;
    std::string cmd_str{command};
    argv.push_back(cmd_str.c_str());
    for (const auto &arg : args) {
      argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    if (options.login_shell) {
      // Execute command in a login shell
      std::string login_shell_cmd = "-l";
      std::string c_arg = "-c";
      std::string full_cmd = cmd_str;
      for (const auto &arg : args) {
        full_cmd += " " + arg;
      }

      const char *args_exec[] = {pw->pw_shell, login_shell_cmd.c_str(), c_arg.c_str(), full_cmd.c_str(), nullptr};
      execvp(pw->pw_shell, const_cast<char *const *>(args_exec));
    } else {
      execvp(cmd_str.c_str(), const_cast<char *const *>(argv.data()));
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
    // Limits removed to allow large operations like pacman -Syu to complete successfully
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
