/**
 * @file config.h
 * @brief Configuration management for Voix
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>
#include <map>
#include <optional>

namespace Voix {

/**
 * @brief Configuration class for Voix settings
 */
class Config {
public:
    Config();
    ~Config();

    /**
     * @brief Load configuration from file
     * @param config_path Path to configuration file
     * @return true if loaded successfully, false otherwise
     */
    bool load(const std::string& config_path = "/etc/voix.conf");

    /**
     * @brief Check if user is allowed to use Voix
     * @param username Username to check
     * @return true if allowed, false otherwise
     */
    bool isUserAllowed(const std::string& username) const;

    /**
     * @brief Get allowed commands for user
     * @param username Username
     * @return Vector of allowed commands
     */
    std::vector<std::string> getAllowedCommands(const std::string& username) const;

    /**
     * @brief Set configuration value
     * @param key Configuration key
     * @param value Configuration value
     */
    void set(const std::string& key, const std::string& value);

    /**
     * @brief Get configuration value
     * @param key Configuration key
     * @return Optional configuration value
     */
    std::optional<std::string> get(const std::string& key) const;

private:
    std::map<std::string, std::string> config_data_;
    std::map<std::string, std::vector<std::string>> user_commands_;

    void parseConfigLine(const std::string& line);
};

} // namespace Config

#endif // CONFIG_H
