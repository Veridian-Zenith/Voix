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
    auto entry = lookup_passwd_by_name(username);
    if (!entry) return std::nullopt;

    // Use getgrouplist() to resolve the target user's supplementary groups
    // (not the calling process's groups, which getgroups() would return)
    std::vector<gid_t> groups;
    int ngroups = 32;
    groups.resize(ngroups);
    if (getgrouplist(username.c_str(), entry->gid, groups.data(), &ngroups) == -1) {
        // Buffer too small, retry with the updated ngroups count
        groups.resize(ngroups);
        if (getgrouplist(username.c_str(), entry->gid, groups.data(), &ngroups) == -1) {
            groups.clear();
            ngroups = 0;
        }
    }
    groups.resize(ngroups);

    return UserIdentity{
        entry->name, entry->uid, entry->gid,
        groups, entry->home_dir, entry->shell
    };
}

std::optional<UserIdentity> SystemIdentity::get_user_by_uid(uid_t uid) const {
    auto entry = lookup_passwd_by_uid(uid);
    if (!entry) return std::nullopt;

    return UserIdentity{
        entry->name, entry->uid, entry->gid,
        {},
        entry->home_dir, entry->shell
    };
}

std::string SystemIdentity::get_current_username() const {
    auto entry = lookup_passwd_by_uid(getuid());
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
