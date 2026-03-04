/**
 * @file config.h
 * @brief Configuration management (placeholder for Lua config)
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "rule.h"
#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace Voix {

class Config {
public:
    Config();
    ~Config() = default;

    bool load(const std::string& config_path);
    std::vector<Rule> getRules() const;

private:
    std::vector<Rule> rules_;
    void parseConfigLine(const std::string& line);
};

} // namespace Voix

#endif // CONFIG_H
