/**
 * @file system_identity.cpp
 * @brief Implementation of system identity operations.
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "system_identity.hpp"
#include "system_utils.hpp"
#include <grp.h>
#include <unistd.h>
#include <vector>

namespace Voix {

std::optional<UserIdentity> SystemIdentity::get_user_by_name(const std::string& username) const {
    auto entry = lookupPasswdByName(username);
    if (!entry) return std::nullopt;

    std::vector<gid_t> groups;
    int ngroups = getgroups(0, nullptr);
    if (ngroups == -1) ngroups = 32;
    groups.resize(ngroups);
    if (getgroups(ngroups, groups.data()) == -1) {
        groups.clear();
    }

    return UserIdentity{
        entry->name, entry->uid, entry->gid,
        groups, entry->home_dir, entry->shell
    };
}

std::optional<UserIdentity> SystemIdentity::get_user_by_uid(uid_t uid) const {
    auto entry = lookupPasswdByUid(uid);
    if (!entry) return std::nullopt;

    return UserIdentity{
        entry->name, entry->uid, entry->gid,
        {},
        entry->home_dir, entry->shell
    };
}

std::string SystemIdentity::get_current_username() const {
    auto entry = lookupPasswdByUid(getuid());
    return entry ? entry->name : "unknown";
}

uid_t SystemIdentity::get_current_uid() const {
    return getuid();
}

std::vector<gid_t> SystemIdentity::get_current_groups() const {
    int ngroups = getgroups(0, nullptr);
    if (ngroups == -1) ngroups = 32;
    std::vector<gid_t> groups(ngroups);
    if (getgroups(ngroups, groups.data()) == -1) {
        return {};
    }
    return groups;
}

} // namespace Voix
