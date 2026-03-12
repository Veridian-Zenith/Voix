#include "system_utils.h"
#include <string>
#include <string_view>
#include <unistd.h>
#include <cstdlib>

namespace Voix {

bool SystemUtils::setUserCredentials(uid_t uid, gid_t gid) const {
  if (setgid(gid) != 0) {
    return false;
  }
  if (setuid(uid) != 0) {
    return false;
  }
  return true;
}

void SystemUtils::setEnvironment(const std::vector<std::string>& env_vars) const {
  for (std::string_view env_var : env_vars) {
    size_t pos = env_var.find('=');
    if (pos != std::string_view::npos) {
      std::string key{env_var.substr(0, pos)};
      std::string value{env_var.substr(pos + 1)};
      setenv(key.c_str(), value.c_str(), 1);
    }
  }
}

} // namespace Voix
