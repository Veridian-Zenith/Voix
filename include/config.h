/**
 * @file config.h
 * @brief Configuration management (placeholder for Lua config)
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace Voix {

class Config {
public:
    Config();
    ~Config();

    bool load(const std::string& config_path);
    bool isUserAllowed(const std::string& username) const;
    std::vector<std::string> getAllowedCommands(const std::string& username) const;
    void set(const std::string& key, const std::string& value);
    std::optional<std::string> get(const std::string& key) const;

private:
    void parseConfigLine(const std::string& line);
};

} // namespace Voix

#endif // CONFIG_H
