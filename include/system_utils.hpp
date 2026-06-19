/**
 * @file system_utils.h
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <sys/types.h>

namespace Voix {
 
constexpr long k_get_pw_buffer_fallback_size = 16384;
constexpr std::string_view privileged_package_manager = "alpm";
 
/**
  * @brief Utility class for system-level operations.
 */
class SystemUtils {
public:
    /**
     * @brief Default constructor for SystemUtils.
     */
    SystemUtils() = default;
    /**
     * @brief Default destructor for SystemUtils.
     */
    ~SystemUtils() = default;

    /**
     * @brief Sets the user credentials (UID and GID) for the current process.
     * @param uid The user ID.
     * @param gid The group ID.
     * @return True if credentials were set successfully, false otherwise.
     */
    bool setUserCredentials(uid_t uid, gid_t gid) const;
    /**
     * @brief Sets the environment variables for the current process.
     * @param env_vars A vector of environment variable strings in "KEY=VALUE" format.
     */
    void setEnvironment(const std::vector<std::string>& env_vars) const;

    /**
     * @brief Retrieves the UID associated with a given username.
     * @param name The username to look up.
     * @return The UID if found, otherwise std::nullopt.
     */
    static std::optional<uid_t> getUidByName(std::string_view name);
    /**
     * @brief Retrieves the GID associated with a given group name.
     * @param name The group name to look up.
     * @return The GID if found, otherwise std::nullopt.
     */
    static std::optional<gid_t> getGidByName(std::string_view name);
};

/**
 * @brief Lightweight result from a passwd database lookup.
 */
struct PasswdEntry {
    std::string name;
    uid_t uid;
    gid_t gid;
    std::string home_dir;
    std::string shell;
};

/**
 * @brief Looks up a passwd entry by username with automatic buffer management.
 * @param name The username to look up.
 * @return The PasswdEntry if found, otherwise std::nullopt.
 */
std::optional<PasswdEntry> lookupPasswdByName(std::string_view name);

/**
 * @brief Looks up a passwd entry by UID with automatic buffer management.
 * @param uid The user ID to look up.
 * @return The PasswdEntry if found, otherwise std::nullopt.
 */
std::optional<PasswdEntry> lookupPasswdByUid(uid_t uid);

} // namespace Voix

#endif // SYSTEM_UTILS_H
