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
#include <sys/capability.h>
#include "config.h"

namespace Voix {

class Security {
public:
    Security();
    ~Security() = default;

    /**
     * @brief Validate user exists and is safe
     * @param username Username to validate
     * @return true if valid, false otherwise
     */
    bool validateUser(std::string_view username) const;



    /**
     * @brief Check if path is safe (no traversal, no sensitive locations)
     * @param path Path to check
     * @return true if safe, false otherwise
     */
    bool isSafePath(std::string_view path) const;

    /**
     * @brief Log security event
     * @param event Event description
     * @param user Username associated with event
     */
    void logEvent(std::string_view event, std::string_view user) const;

    /**
     * @brief Get current user name
     * @return Current user name
     */
    std::string getCurrentUser() const;

    /**
     * @brief Prevent unequivocally destructive commands (e.g. rm -rf /)
     * @param command Command to check
     * @param args Command arguments
     * @param config Configuration instance for blocklist
     * @return true if catastrophic, false otherwise
     */
    bool isCatastrophicCommand(std::string_view command, const std::vector<std::string>& args, const Config& config) const;

    /**
     * @brief Raise capabilities to perform privileged operations.
     */
    void raiseCapabilities();

    /**
     * @brief Drop all capabilities, optionally keeping some.
     * @param keep_caps Vector of capabilities to keep.
     */
    void dropCapabilities(const std::vector<cap_value_t>& keep_caps = {});

    /**
     * @brief Apply Seccomp blacklist to restrict dangerous system calls.
     */
    void applySeccompBlacklist() const;

private:

};

} // namespace Voix

#endif // SECURITY_H
