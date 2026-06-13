/**
 * @file system_identity.cpp
 * @brief Implementation of system identity operations.
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "system_identity.hpp"
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <vector>
#include <string>

namespace Voix {

std::optional<UserIdentity> SystemIdentity::getUserByName(const std::string& username) const {
    struct passwd pwd;
    struct passwd* result = nullptr;
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;
    std::vector<char> buffer(static_cast<size_t>(bufsize));

    if (getpwnam_r(username.c_str(), &pwd, buffer.data(), buffer.size(), &result) != 0 || result == nullptr) {
        return std::nullopt;
    }

    std::vector<gid_t> groups;
    int ngroups = getgroups(0, nullptr);
    if (ngroups == -1) ngroups = 32;
    groups.resize(ngroups);
    if (getgroups(ngroups, groups.data()) == -1) {
        groups.clear();
    }

    return UserIdentity{
        result->pw_name,
        result->pw_uid,
        result->pw_gid,
        groups,
        result->pw_dir,
        result->pw_shell
    };
}

std::optional<UserIdentity> SystemIdentity::getUserByUid(uid_t uid) const {
    struct passwd pwd;
    struct passwd* result = nullptr;
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;
    std::vector<char> buffer(static_cast<size_t>(bufsize));

    if (getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result) != 0 || result == nullptr) {
        return std::nullopt;
    }

    return UserIdentity{
        result->pw_name,
        result->pw_uid,
        result->pw_gid,
        {}, // Groups not typically fetched by uid alone without getgroups
        result->pw_dir,
        result->pw_shell
    };
}

std::string SystemIdentity::getCurrentUsername() const {
    uid_t uid = getuid();
    struct passwd pwd;
    struct passwd* result = nullptr;
    long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;
    std::vector<char> buffer(static_cast<size_t>(bufsize));

    if (getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result) == 0 && result != nullptr) {
        return std::string(result->pw_name);
    }
    return "unknown";
}

uid_t SystemIdentity::getCurrentUid() const {
    return getuid();
}

std::vector<gid_t> SystemIdentity::getCurrentGroups() const {
    int ngroups = getgroups(0, nullptr);
    if (ngroups == -1) ngroups = 32;
    std::vector<gid_t> groups(ngroups);
    if (getgroups(ngroups, groups.data()) == -1) {
        return {};
    }
    return groups;
}

} // namespace Voix
