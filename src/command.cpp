/**
 * @file command.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "command.h"
#include <pwd.h>
#include <grp.h>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <cstdlib>
#include <utility>

namespace Voix {

int Command::execute(std::string_view command,
                     const std::vector<std::string>& args,
                     std::string_view user) const {
  pid_t pid = fork();

  if (pid == -1) {
    return -1;
  } else if (pid == 0) {
    std::string user_str{user};
    struct passwd *pw = getpwnam(user.empty() ? "root" : user_str.c_str());
    if (!pw) {
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

    // Scrub the environment
    clearenv();
    
    // Restore whitelist & explicitly set target identity
    for (const auto& env : saved_env) {
      setenv(env.first.c_str(), env.second.c_str(), 1);
    }
    setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", 1);
    setenv("USER", pw->pw_name, 1);
    setenv("LOGNAME", pw->pw_name, 1);
    setenv("HOME", pw->pw_dir, 1);

    // Prevent FD leakage
    int max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 4096) max_fd = 4096;
    for (int i = 3; i < max_fd; ++i) {
      close(i);
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
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    }
    return -1;
  }
}

std::string Command::buildCommandString(std::string_view command,
                                        const std::vector<std::string>& args,
                                        std::string_view user) const {
  std::stringstream ss;
  if (!user.empty() && user != "root") {
    ss << "su - " << user << " -c ";
  }
  ss << command;
  for (const auto &arg : args) {
    ss << " " << arg;
  }
  return ss.str();
}

} // namespace Voix
