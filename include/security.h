/**
 * @file security.h
 * @brief Enhanced security and validation
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef SECURITY_H
#define SECURITY_H

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <memory>
#ifdef VOIX_WITH_CAP
#include <sys/capability.h>
#endif
#include "config.h"
#include "system_identity.h"

namespace Voix {

class Security {
public:
    /**
     * @brief Constructor for Security.
     * @param identity An optional identity provider. Defaults to SystemIdentity.
     */
    Security(std::shared_ptr<IIdentity> identity = std::make_shared<SystemIdentity>());
    /**
     * @brief Default destructor for Security.
     */
    ~Security() = default;

    /**
     * @brief Validates that a user exists and is considered safe.
     * @param username Username to validate.
     * @return True if valid, false otherwise.
     */
    bool validateUser(std::string_view username) const;



    /**
     * @brief Checks if a path is safe (e.g., no directory traversal, no sensitive locations).
     * @param path Path to check.
     * @return True if safe, false otherwise.
     */
    bool isSafePath(std::string_view path) const;

    /**
     * @brief Logs a security-related event.
     * @param event Description of the event.
     * @param user Username associated with the event.
     */
    void logEvent(std::string_view event, std::string_view user) const;

    /**
     * @brief Gets the current username.
     * @return The current username.
     */
    std::string getCurrentUser() const;
    /**
     * @brief Gets the current user ID.
     * @return The current UID.
     */
    uid_t getCurrentUid() const;

    /**
     * @brief Prevents unequivocally destructive commands (e.g., 'rm -rf /').
     * @param command Command to check.
     * @param args Command arguments.
     * @param config Configuration instance for the blocklist.
     * @return True if the command is catastrophic, false otherwise.
     */
    bool isCatastrophicCommand(std::string_view command, const std::vector<std::string>& args, const Config& config) const;

#ifdef VOIX_WITH_CAP
    /**
     * @brief Raises capabilities to perform privileged operations.
     */
    void raiseCapabilities();

    /**
     * @brief Drops all capabilities, optionally keeping some.
     * @param keep_caps Vector of capabilities to retain.
     */
    void dropCapabilities(const std::vector<cap_value_t>& keep_caps = {});
#endif
#ifdef VOIX_WITH_SECCOMP
    /**
     * @brief Applies a Seccomp blacklist to restrict dangerous system calls.
     */
    void applySeccompBlacklist() const;
#endif


    std::shared_ptr<IIdentity> identity_;

};

} // namespace Voix

#endif // SECURITY_H
