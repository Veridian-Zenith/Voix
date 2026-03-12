/**
 * @file security.h
 * @brief Enhanced security and validation
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef SECURITY_H
#define SECURITY_H

#include <string>
#include <string_view>
#include <vector>
#include <optional>

namespace Voix {

class Security {
public:
    Security();
    ~Security();

    /**
     * @brief Validate user exists and is safe
     * @param username Username to validate
     * @return true if valid, false otherwise
     */
    bool validateUser(std::string_view username) const;

    /**
     * @brief Validate command and arguments
     * @param command Command to validate
     * @param args Command arguments
     * @return true if valid, false otherwise
     */
    bool validateCommand(std::string_view command,
                         const std::vector<std::string>& args) const;

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
     * @brief Check if command is dangerous
     * @param command Command to check
     * @return true if dangerous, false otherwise
     */
    bool isDangerousCommand(std::string_view command) const;

    /**
     * @brief Check if string contains shell metacharacters
     * @param str String to check
     * @return true if contains dangerous characters, false otherwise
     */
    bool containsShellMetacharacters(std::string_view str) const;

private:
    // Enhanced dangerous command list
    const std::vector<std::string> dangerous_commands_;
    const std::string dangerous_chars_;
};

} // namespace Voix

#endif // SECURITY_H
