/**
 * @file config.cpp
 * @brief Configuration management implementation
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include "config.h"
#include <fstream>
#include <sstream>
#include <algorithm>

namespace Voix {

Config::Config() = default;

Config::~Config() = default;

bool Config::load(const std::string& config_path) {
    std::ifstream config_file(config_path);
    if (!config_file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(config_file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        parseConfigLine(line);
    }

    config_file.close();
    return true;
}

bool Config::isUserAllowed(const std::string& username) const {
    // Check if user is in the allowed users list
    auto allowed_users = config_data_.find("allowed_users");
    if (allowed_users != config_data_.end()) {
        // Simple comma-separated list parsing
        std::istringstream stream(allowed_users->second);
        std::string user;
        while (std::getline(stream, user, ',')) {
            // Trim whitespace
            user.erase(0, user.find_first_not_of(" \t"));
            user.erase(user.find_last_not_of(" \t") + 1);
            if (user == username) {
                return true;
            }
        }
    }

    // Check if user has specific command permissions
    auto user_commands = user_commands_.find(username);
    return user_commands != user_commands_.end();
}

std::vector<std::string> Config::getAllowedCommands(const std::string& username) const {
    auto user_commands = user_commands_.find(username);
    if (user_commands != user_commands_.end()) {
        return user_commands->second;
    }
    return {};
}

void Config::set(const std::string& key, const std::string& value) {
    config_data_[key] = value;
}

std::optional<std::string> Config::get(const std::string& key) const {
    auto it = config_data_.find(key);
    if (it != config_data_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void Config::parseConfigLine(const std::string& line) {
    // First check if this is a user-specific command line (contains ':' but not '=')
    if (line.find(':') != std::string::npos && line.find('=') == std::string::npos) {
        std::istringstream stream(line);
        std::string username, commands;
        if (std::getline(stream, username, ':') && std::getline(stream, commands)) {
            // Trim whitespace
            username.erase(0, username.find_first_not_of(" \t"));
            username.erase(username.find_last_not_of(" \t") + 1);
            commands.erase(0, commands.find_first_not_of(" \t"));
            commands.erase(commands.find_last_not_of(" \t") + 1);

            // Parse comma-separated command list
            std::vector<std::string> cmd_list;
            std::istringstream cmd_stream(commands);
            std::string cmd;
            while (std::getline(cmd_stream, cmd, ',')) {
                cmd.erase(0, cmd.find_first_not_of(" \t"));
                cmd.erase(cmd.find_last_not_of(" \t") + 1);
                if (!cmd.empty()) {
                    cmd_list.push_back(cmd);
                }
            }
            user_commands_[username] = cmd_list;
        }
    }
    // Handle global configuration (contains '=')
    else if (line.find('=') != std::string::npos) {
        std::istringstream stream(line);
        std::string key, value;
        if (std::getline(stream, key, '=') && std::getline(stream, value)) {
            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            config_data_[key] = value;
        }
    }
}

} // namespace Config
