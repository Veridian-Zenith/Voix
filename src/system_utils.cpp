/**
 * @file system_utils.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "system_utils.hpp"
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

std::optional<uid_t> SystemUtils::getUidByName(std::string_view name) {
    auto entry = lookupPasswdByName(name);
    if (!entry) return std::nullopt;
    return entry->uid;
}

std::optional<gid_t> SystemUtils::getGidByName(std::string_view name) {
    struct group grp;
    struct group *result;
    std::vector<char> buf(1024);
    int s;
    std::string name_str(name);

    while (true) {
        s = getgrnam_r(name_str.c_str(), &grp, buf.data(), buf.size(), &result);
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

namespace {
    std::vector<char> make_passwd_buffer() {
        long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize == -1) bufsize = Voix::k_get_pw_buffer_fallback_size;
        return std::vector<char>(static_cast<size_t>(bufsize));
    }
}

std::optional<PasswdEntry> lookupPasswdByName(std::string_view name) {
    struct passwd pwd;
    struct passwd *result = nullptr;
    auto buf = make_passwd_buffer();
    std::string name_str(name);

    while (true) {
        int s = getpwnam_r(name_str.c_str(), &pwd, buf.data(), buf.size(), &result);
        if (s == ERANGE) {
            buf.resize(buf.size() * 2);
        } else {
            break;
        }
    }

    if (!result) return std::nullopt;
    return PasswdEntry{result->pw_name, result->pw_uid, result->pw_gid,
                       result->pw_dir, result->pw_shell};
}

std::optional<PasswdEntry> lookupPasswdByUid(uid_t uid) {
    struct passwd pwd;
    struct passwd *result = nullptr;
    auto buf = make_passwd_buffer();

    while (true) {
        int s = getpwuid_r(uid, &pwd, buf.data(), buf.size(), &result);
        if (s == ERANGE) {
            buf.resize(buf.size() * 2);
        } else {
            break;
        }
    }

    if (!result) return std::nullopt;
    return PasswdEntry{result->pw_name, result->pw_uid, result->pw_gid,
                       result->pw_dir, result->pw_shell};
}

} // namespace Voix
