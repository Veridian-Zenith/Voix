/**
 * @file pam_auth.h
 * @brief Independent authentication for Voix
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef PAM_AUTH_H
#define PAM_AUTH_H

#include <string>
#include <optional>
#include <vector>

namespace Voix {

/**
 * @brief Independent authentication class for Voix (no sudo/doas dependency)
 */
class PAMAuth {
public:
    PAMAuth();
    ~PAMAuth();

    /**
     * @brief Authenticate user using independent Voix system
     * @param username Username to authenticate
     * @return true if authenticated, false otherwise
     */
    bool authenticate(const std::string& username) const;

    /**
     * @brief Check if user exists in system
     * @param username Username to check
     * @return true if exists, false otherwise
     */
    bool userExists(const std::string& username) const;

    /**
     * @brief Get user's groups
     * @param username Username
     * @return Vector of group names
     */
    std::vector<std::string> getUserGroups(const std::string& username) const;

    /**
     * @brief Check if user is in admin groups
     * @param username Username to check
     * @return true if allowed, false otherwise
     */
    bool isInAdminGroup(const std::string& username) const;

    /**
     * @brief Check if user is in Voix-specific admin groups
     * @param username Username to check
     * @return true if in Voix admin group, false otherwise
     */
    bool isInVoixAdminGroup(const std::string& username) const;

    /**
     * @brief Check if user is in wheel group (always allowed)
     * @param username Username to check
     * @return true if in wheel group, false otherwise
     */
    bool isInWheelGroup(const std::string& username) const;

    /**
     * @brief Read sudoers configuration (returns empty - Voix doesn't use sudoers)
     * @return Vector of allowed users
     */
    std::vector<std::string> getSudoersUsers() const;

    /**
     * @brief Check if user has sudo privileges (always returns false)
     * @param username Username to check
     * @return always false - Voix doesn't rely on sudo privileges
     */
    bool hasSudoPrivilege(const std::string& username) const;

    /**
     * @brief Check if user is explicitly allowed in Voix configuration
     * @param username Username to check
     * @return true if allowed in config, false otherwise
     */
    bool isAllowedInVoixConfig(const std::string& username) const;

private:
    bool readPAMConfig() const;
    bool createDefaultVoixPAMConfig() const;
    std::optional<std::string> readFile(const std::string& path) const;
    std::vector<std::string> parseGroupFile(const std::string& group_name) const;
    std::vector<std::string> readVoixAllowedUsers() const;
    std::vector<std::string> readVoixAllowedGroups() const;
};

} // namespace PAMAuth

#endif // PAM_AUTH_H
