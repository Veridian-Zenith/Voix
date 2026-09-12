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
#include <shadow.h>
#include <vector>

namespace Voix {

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
    auto entry = lookup_passwd_by_name(name);
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

std::optional<PasswdEntry> lookup_passwd_by_name(std::string_view name) {
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

std::optional<PasswdEntry> lookup_passwd_by_uid(uid_t uid) {
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

bool user_has_password(std::string_view username) {
    std::string name_str(username);
    struct spwd *sp = getspnam(name_str.c_str());
    if (!sp) {
        // No shadow entry — fall back to passwd.  If pw_passwd is 'x' the
        // real hash lives in shadow and getspnam should have found it;
        // a missing shadow entry with pw_passwd != 'x' means no password.
        auto pw = lookup_passwd_by_name(username);
        if (!pw) return false;
        // getpwnam fills pw_passwd only when shadow is not in use.
        // We cannot read pw_passwd from the PasswdEntry struct (it is not
        // stored), so we re-read it here.
        struct passwd pwd;
        struct passwd *result = nullptr;
        auto buf = make_passwd_buffer();
        while (true) {
            int s = getpwnam_r(name_str.c_str(), &pwd, buf.data(), buf.size(), &result);
            if (s == ERANGE) {
                buf.resize(buf.size() * 2);
            } else {
                break;
            }
        }
        if (!result) return false;
        std::string_view pw_passwd = result->pw_passwd;
        // If pw_passwd is 'x', shadow is used but entry was missing —
        // treat as no password.
        if (pw_passwd.empty() || pw_passwd == "x" || pw_passwd == "!*" ||
            pw_passwd == "!!" || pw_passwd.starts_with("!") ||
            pw_passwd.starts_with("*")) {
            return false;
        }
        return true;
    }

    std::string_view hash = sp->sp_pwdp;
    // Disabled/locked accounts: empty, "!", "*", "!!", or "!..." prefix
    return !hash.empty() && hash != "!" && hash != "*" && hash != "!!" &&
           !hash.starts_with("!") && !hash.starts_with("*");
}

} // namespace Voix
