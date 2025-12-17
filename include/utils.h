/**
 * @file utils.h
 * @brief Utility functions for Voix
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <optional>

namespace Voix {

/**
 * @brief Utility class for common functions
 */
class Utils {
public:
    Utils();
    ~Utils();

    /**
     * @brief Execute a system command
     * @param command Command to execute
     * @param args Command arguments
     * @param user Target user (optional)
     * @return Exit code of the command
     */
    int executeCommand(const std::string& command,
                      const std::vector<std::string>& args = {},
                      const std::optional<std::string>& user = std::nullopt) const;

    /**
     * @brief Check if file exists
     * @param path File path
     * @return true if exists, false otherwise
     */
    bool fileExists(const std::string& path) const;

    /**
     * @brief Read file content
     * @param path File path
     * @return File content as string
     */
    std::optional<std::string> readFile(const std::string& path) const;

    /**
     * @brief Write content to file
     * @param path File path
     * @param content Content to write
     * @return true if successful, false otherwise
     */
    bool writeFile(const std::string& path, const std::string& content) const;

    /**
     * @brief Get current timestamp
     * @return Current timestamp as string
     */
    std::string getTimestamp() const;

    /**
     * @brief Log message to syslog or file
     * @param level Log level
     * @param message Message to log
     */
    void log(const std::string& level, const std::string& message) const;

private:
    std::string buildCommandString(const std::string& command,
                                  const std::vector<std::string>& args,
                                  const std::optional<std::string>& user) const;
};

} // namespace Utils

#endif // UTILS_H
