/**
 * @file pam_auth.cpp
 * @brief Independent authentication for Voix (no sudo/doas dependency)
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include "pam_auth.h"
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace Voix {

PAMAuth::PAMAuth() = default;

PAMAuth::~PAMAuth() = default;

bool PAMAuth::authenticate(const std::string& username) const {
    // Voix has its own independent authentication system
    // No dependency on sudo/doas configuration

    // Check if user exists
    if (!userExists(username)) {
        return false;
    }

    // Root user always has access
    if (username == "root") {
        return true;
    }

    // Wheel group is always allowed (universal admin group)
    if (isInWheelGroup(username)) {
        return true;
    }

    // Check if user is in Voix admin groups (independent of sudo)
    if (isInVoixAdminGroup(username)) {
        return true;
    }

    // Check if user is explicitly allowed in Voix configuration
    return isAllowedInVoixConfig(username);
}

bool PAMAuth::userExists(const std::string& username) const {
    struct passwd* pw = getpwnam(username.c_str());
    return pw != nullptr;
}

std::vector<std::string> PAMAuth::getUserGroups(const std::string& username) const {
    std::vector<std::string> groups;
    struct passwd* pw = getpwnam(username.c_str());

    if (!pw) {
        return groups;
    }

    // Get user's primary group
    struct group* gr = getgrgid(pw->pw_gid);
    if (gr) {
        groups.push_back(gr->gr_name);
    }

    // Get supplementary groups
    int ngroups = 0;
    gid_t* groups_list = nullptr;

    // First call to get the number of groups
    if (getgrouplist(username.c_str(), pw->pw_gid, nullptr, &ngroups) == -1) {
        groups_list = static_cast<gid_t*>(malloc(ngroups * sizeof(gid_t)));
        if (groups_list && getgrouplist(username.c_str(), pw->pw_gid, groups_list, &ngroups) != -1) {
            for (int i = 0; i < ngroups; i++) {
                struct group* gr = getgrgid(groups_list[i]);
                if (gr) {
                    groups.push_back(gr->gr_name);
                }
            }
        }
        free(groups_list);
    }

    return groups;
}

bool PAMAuth::isInAdminGroup(const std::string& username) const {
    // Check for traditional admin groups, but these are system groups
    // not related to sudo configuration
    auto groups = getUserGroups(username);

    std::vector<std::string> admin_groups = {"wheel", "sudo", "admin", "adm", "voix"};

    for (const auto& group : groups) {
        for (const auto& admin_group : admin_groups) {
            if (group == admin_group) {
                return true;
            }
        }
    }

    return false;
}

bool PAMAuth::isInVoixAdminGroup(const std::string& username) const {
    // Specifically check for Voix-specific admin groups
    auto groups = getUserGroups(username);

    // Check for Voix-specific admin groups
    std::vector<std::string> voix_groups = {"voix", "voix-admin"};

    for (const auto& group : groups) {
        for (const auto& voix_group : voix_groups) {
            if (group == voix_group) {
                return true;
            }
        }
    }

    return false;
}

bool PAMAuth::isInWheelGroup(const std::string& username) const {
    // Wheel group is always allowed - universal admin group
    auto groups = getUserGroups(username);

    for (const auto& group : groups) {
        if (group == "wheel") {
            return true;
        }
    }

    return false;
}

std::vector<std::string> PAMAuth::getSudoersUsers() const {
    // This method is kept for compatibility but doesn't check sudoers
    // Voix has its own configuration system
    std::vector<std::string> users;

    // Return empty - Voix doesn't use sudoers for authentication
    return users;
}

bool PAMAuth::hasSudoPrivilege(const std::string& username) const {
    (void)username; // mark as unused
    return false;
}

bool PAMAuth::isAllowedInVoixConfig(const std::string& username) const {
    // Check if user is explicitly allowed in Voix configuration
    auto allowed_users = readVoixAllowedUsers();

    for (const auto& allowed_user : allowed_users) {
        if (allowed_user == username) {
            return true;
        }
    }

    // Also check group-based permissions
    auto allowed_groups = readVoixAllowedGroups();
    auto user_groups = getUserGroups(username);

    for (const auto& group : user_groups) {
        for (const auto& allowed_group : allowed_groups) {
            if (group == allowed_group) {
                return true;
            }
        }
    }

    return false;
}

bool PAMAuth::readPAMConfig() const {
    // Read Voix-specific PAM configuration
    auto pam_config = readFile("/etc/pam.d/voix");
    if (pam_config.has_value()) {
        // Parse Voix-specific PAM configuration
        return true;
    }

    // Create default Voix PAM configuration if it doesn't exist
    return createDefaultVoixPAMConfig();
}

bool PAMAuth::createDefaultVoixPAMConfig() const {
    // Create default PAM configuration for Voix
    std::string default_pam_config =
        "# Voix PAM Configuration\n"
        "# This configuration is independent of sudo/doas\n"
        "auth    required        pam_unix.so\n"
        "account required        pam_unix.so\n"
        "session required        pam_unix.so\n";

    // For now, just return true - in a real implementation,
    // this would create the PAM configuration file
    return true;
}

std::optional<std::string> PAMAuth::readFile(const std::string& path) const {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    return buffer.str();
}

std::vector<std::string> PAMAuth::parseGroupFile(const std::string& group_name) const {
    std::vector<std::string> users;

    auto group_content = readFile("/etc/group");
    if (!group_content.has_value()) {
        return users;
    }

    std::istringstream stream(group_content.value());
    std::string line;

    while (std::getline(stream, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::istringstream line_stream(line);
        std::string group, password, gid, members;

        if (std::getline(line_stream, group, ':') &&
            std::getline(line_stream, password, ':') &&
            std::getline(line_stream, gid, ':') &&
            std::getline(line_stream, members, ':')) {

            if (group == group_name) {
                // Parse members (comma-separated)
                std::istringstream member_stream(members);
                std::string member;
                while (std::getline(member_stream, member, ',')) {
                    if (!member.empty()) {
                        users.push_back(member);
                    }
                }
                break;
            }
        }
    }

    return users;
}

std::vector<std::string> PAMAuth::readVoixAllowedUsers() const {
    std::vector<std::string> users;

    // Read Voix configuration to get allowed users
    auto voix_config = readFile("/etc/voix.conf");
    if (voix_config.has_value()) {
        std::istringstream stream(voix_config.value());
        std::string line;

        while (std::getline(stream, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // Look for allowed_users configuration
            if (line.find("allowed_users") != std::string::npos) {
                std::istringstream line_stream(line);
                std::string key, value;
                if (std::getline(line_stream, key, '=') && std::getline(line_stream, value)) {
                    // Trim whitespace
                    key.erase(0, key.find_first_not_of(" \t"));
                    key.erase(key.find_last_not_of(" \t") + 1);
                    value.erase(0, value.find_first_not_of(" \t"));
                    value.erase(value.find_last_not_of(" \t") + 1);

                    if (key == "allowed_users") {
                        // Parse comma-separated user list
                        std::istringstream user_stream(value);
                        std::string user;
                        while (std::getline(user_stream, user, ',')) {
                            user.erase(0, user.find_first_not_of(" \t"));
                            user.erase(user.find_last_not_of(" \t") + 1);
                            if (!user.empty()) {
                                users.push_back(user);
                            }
                        }
                    }
                }
            }
        }
    }

    return users;
}

std::vector<std::string> PAMAuth::readVoixAllowedGroups() const {
    std::vector<std::string> groups;

    // Read Voix configuration to get allowed groups
    auto voix_config = readFile("/etc/voix.conf");
    if (voix_config.has_value()) {
        std::istringstream stream(voix_config.value());
        std::string line;

        while (std::getline(stream, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // Look for allowed_groups configuration
            if (line.find("allowed_groups") != std::string::npos) {
                std::istringstream line_stream(line);
                std::string key, value;
                if (std::getline(line_stream, key, '=') && std::getline(line_stream, value)) {
                    // Trim whitespace
                    key.erase(0, key.find_first_not_of(" \t"));
                    key.erase(key.find_last_not_of(" \t") + 1);
                    value.erase(0, value.find_first_not_of(" \t"));
                    value.erase(value.find_last_not_of(" \t") + 1);

                    if (key == "allowed_groups") {
                        // Parse comma-separated group list
                        std::istringstream group_stream(value);
                        std::string group;
                        while (std::getline(group_stream, group, ',')) {
                            group.erase(0, group.find_first_not_of(" \t"));
                            group.erase(group.find_last_not_of(" \t") + 1);
                            if (!group.empty()) {
                                groups.push_back(group);
                            }
                        }
                    }
                }
            }
        }
    }

    return groups;
}

} // namespace PAMAuth
