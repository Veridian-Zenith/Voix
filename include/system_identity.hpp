/**
 * @file system_identity.h
 * @brief Interface for system identity operations to allow mocking in tests.
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef SYSTEM_IDENTITY_H
#define SYSTEM_IDENTITY_H

#include <string>
#include <vector>
#include <sys/types.h>
#include <optional>

namespace Voix {

/**
 * @brief Represents identity information for a system user.
 */
struct UserIdentity {
    std::string username;      /**< The username. */
    uid_t uid;                 /**< The user ID. */
    gid_t gid;                 /**< The primary group ID. */
    std::vector<gid_t> groups; /**< The list of supplementary group IDs. */
    std::string home_dir;      /**< The user's home directory. */
    std::string shell;         /**< The user's login shell. */
};

/**
 * @brief Interface for system identity operations to allow mocking in tests.
 */
class IIdentity {
public:
    virtual ~IIdentity() = default;
    /**
     * @brief Retrieves user identity information by username.
     * @param username The username to look up.
     * @return The UserIdentity if found, otherwise std::nullopt.
     */
    virtual std::optional<UserIdentity> getUserByName(const std::string& username) const = 0;
    /**
     * @brief Retrieves user identity information by UID.
     * @param uid The user ID to look up.
     * @return The UserIdentity if found, otherwise std::nullopt.
     */
    virtual std::optional<UserIdentity> getUserByUid(uid_t uid) const = 0;
    /**
     * @brief Retrieves the current username.
     * @return The current username.
     */
    virtual std::string getCurrentUsername() const = 0;
    /**
     * @brief Retrieves the current UID.
     * @return The current user ID.
     */
    virtual uid_t getCurrentUid() const = 0;
    /**
     * @brief Retrieves the current user's groups.
     * @return A vector of group IDs.
     */
    virtual std::vector<gid_t> getCurrentGroups() const = 0;
};

/**
 * @brief Concrete implementation of IIdentity using system calls.
 */
class SystemIdentity : public IIdentity {
public:
    std::optional<UserIdentity> getUserByName(const std::string& username) const override;
    std::optional<UserIdentity> getUserByUid(uid_t uid) const override;
    std::string getCurrentUsername() const override;
    uid_t getCurrentUid() const override;
    std::vector<gid_t> getCurrentGroups() const override;
};

} // namespace Voix

#endif // SYSTEM_IDENTITY_H
