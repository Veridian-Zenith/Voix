/**
 * @file utils.h
 * @brief Utility functions with OpenDoas enhancements
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <optional>
#include <sys/types.h>

namespace Voix {

class Utils {
public:
    Utils();
    ~Utils();

    /**
     * @brief Execute command with enhanced security
     * @param command Command to execute
     * @param args Command arguments
     * @param user Target user (optional)
     * @return Exit code of the command
     */
    int executeCommand(const std::string& command,
                       const std::vector<std::string>& args,
                       const std::string& user = "root") const;

    /**
     * @brief Check if file exists
     * @param path Path to check
     * @return true if exists, false otherwise
     */
    bool fileExists(const std::string& path) const;

    /**
     * @brief Read file contents
     * @param path Path to file
     * @return File contents or empty if error
     */
    std::optional<std::string> readFile(const std::string& path) const;

    /**
     * @brief Write file with contents
     * @param path Path to file
     * @param content Content to write
     * @return true if successful, false otherwise
     */
    bool writeFile(const std::string& path, const std::string& content) const;

    /**
     * @brief Get current timestamp
     * @return Timestamp string
     */
    std::string getTimestamp() const;

    /**
     * @brief Log message with timestamp
     * @param level Log level
     * @param message Message to log
     */
    void log(const std::string& level, const std::string& message) const;

    /**
     * @brief Build command string for logging
     * @param command Command
     * @param args Arguments
     * @param user Target user
     * @return Formatted command string
     */
    std::string buildCommandString(const std::string& command,
                                  const std::vector<std::string>& args,
                                  const std::string& user) const;

    /**
     * @brief Set user credentials (OpenDoas-style)
     * @param uid Target user ID
     * @param gid Target group ID
     * @return true if successful, false otherwise
     */
    bool setUserCredentials(uid_t uid, gid_t gid) const;

    /**
     * @brief Set environment variables
     * @param env_vars Environment variables to set
     */
    void setEnvironment(const std::vector<std::string>& env_vars) const;
};

} // namespace Voix

#endif // UTILS_H
