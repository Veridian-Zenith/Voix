#include "command.h"
#include <pwd.h>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

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
    if (pw) {
      if (setgid(pw->pw_gid) != 0) {
        _exit(1);
      }
      if (setuid(pw->pw_uid) != 0) {
        _exit(1);
      }
    } else {
      _exit(1);
    }

    std::vector<const char *> argv;
    std::string cmd_str{command};
    argv.push_back(cmd_str.c_str());
    for (const auto &arg : args) {
      argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    setenv("PATH",
           "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", 1);

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
