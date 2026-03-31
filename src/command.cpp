/**
 * @file command.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "command.h"
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
#include "logger.h"

namespace Voix {

int Command::execute(std::string_view command, const std::vector<std::string>& args,
                      const Config& config, std::string_view user) const {
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
    std::vector<std::string> whitelist = {"TERM", "DISPLAY", "XAUTHORITY", "LANG"};
    std::vector<std::pair<std::string, std::string>> saved_env;
    for (const auto& var : whitelist) {
      if (const char* val = getenv(var.c_str())) {
        saved_env.push_back({var, val});
      }
    }

    // Drop privileges completely
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) _exit(1);
    if (setgid(pw->pw_gid) != 0) _exit(1);
    if (setuid(pw->pw_uid) != 0) _exit(1);

    // Change to sanctuary directory
    if (chdir(config.getSanctuary().c_str()) != 0) {
        LOG_ERROR("Failed to change directory to sanctuary");
        _exit(1);
    }

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

    // Prevent FD leakage
    setResourceLimits();
    bool closed = false;
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3, ~0U, 0) == 0) {
      closed = true;
    }
#endif

    if (!closed) {
      int max_fd = sysconf(_SC_OPEN_MAX);
      if (max_fd < 0 || max_fd > 4096) max_fd = 4096;
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

    execvp(cmd_str.c_str(), const_cast<char *const *>(argv.data()));
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
    struct rlimit cpu_limit;
    cpu_limit.rlim_cur = 60; // 60 seconds
    cpu_limit.rlim_max = 60;
    if (setrlimit(RLIMIT_CPU, &cpu_limit) != 0) {
        LOG_WARN("Failed to set CPU time limit");
    }

    struct rlimit mem_limit;
    mem_limit.rlim_cur = 1024 * 1024 * 100; // 100 MB
    mem_limit.rlim_max = 1024 * 1024 * 100;
    if (setrlimit(RLIMIT_AS, &mem_limit) != 0) {
        LOG_WARN("Failed to set memory limit");
    }

    struct rlimit nofile_limit;
    nofile_limit.rlim_cur = 256;
    nofile_limit.rlim_max = 256;
    if (setrlimit(RLIMIT_NOFILE, &nofile_limit) != 0) {
        LOG_WARN("Failed to set file descriptor limit");
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
