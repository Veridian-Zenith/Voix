/**
 * @file security.h
 * @brief Security and validation for Voix
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef SECURITY_H
#define SECURITY_H

#include <string>
#include <vector>
#include <optional>

namespace Voix {

/**
 * @brief Security class for Voix validation and checks
 */
class Security {
public:
    Security();
    ~Security();

    /**
     * @brief Validate user permissions
     * @param username Username to validate
     * @return true if valid, false otherwise
     */
    bool validateUser(const std::string& username) const;

    /**
     * @brief Validate command for security
     * @param command Command to validate
     * @param args Command arguments
     * @return true if safe, false otherwise
     */
    bool validateCommand(const std::string& command,
                        const std::vector<std::string>& args) const;

    /**
     * @brief Check if path is safe
     * @param path Path to check
     * @return true if safe, false otherwise
     */
    bool isSafePath(const std::string& path) const;

    /**
     * @brief Log security event
     * @param event Security event description
     * @param user User who triggered the event
     */
    void logEvent(const std::string& event, const std::string& user) const;

    /**
     * @brief Get current user information
     * @return Current username
     */
    std::string getCurrentUser() const;

private:
    bool isDangerousCommand(const std::string& command) const;
    bool containsShellMetacharacters(const std::string& str) const;
};

} // namespace Security

#endif // SECURITY_H
