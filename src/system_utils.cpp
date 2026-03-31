/**
 * @file system_utils.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "system_utils.h"
#include <string>
#include <string_view>
#include <unistd.h>
#include <cstdlib>
#include <pwd.h>
#include <grp.h>
#include <vector>

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

std::optional<uid_t> SystemUtils::getUidByName(const std::string& name) {
    struct passwd pwd;
    struct passwd *result;
    std::vector<char> buf(1024);
    int s;

    while (true) {
        s = getpwnam_r(name.c_str(), &pwd, buf.data(), buf.size(), &result);
        if (s == ERANGE) {
            buf.resize(buf.size() * 2);
        } else {
            break;
        }
    }

    if (result == nullptr) {
        return std::nullopt;
    }
    return result->pw_uid;
}

std::optional<gid_t> SystemUtils::getGidByName(const std::string& name) {
    struct group grp;
    struct group *result;
    std::vector<char> buf(1024);
    int s;

    while (true) {
        s = getgrnam_r(name.c_str(), &grp, buf.data(), buf.size(), &result);
        if (s == ERANGE) {
            buf.resize(buf.size() * 2);
        } else {
            break;
        }
    }

    if (result == nullptr) {
        return std::nullopt;
    }
    return result->gr_gid;
}

} // namespace Voix
