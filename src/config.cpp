/**
 * @file config.cpp
 * @brief Basic configuration implementation (stub)
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include "config.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <optional>

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

bool Config::isUserAllowed(const std::string& /*username*/) const {
    // Stub implementation - always return false
    // In real implementation, this would check config
    return false;
}

std::vector<std::string> Config::getAllowedCommands(const std::string& /*username*/) const {
    // Stub implementation - return empty vector
    return {};
}

void Config::set(const std::string& /*key*/, const std::string& /*value*/) {
    // Stub implementation
}

std::optional<std::string> Config::get(const std::string& /*key*/) const {
    // Stub implementation - return empty
    return std::nullopt;
}

void Config::parseConfigLine(const std::string& /*line*/) {
    // Stub implementation
}

} // namespace Voix
