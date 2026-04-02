/**
 * @file config.h
 * @brief Configuration management
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "rule.h"
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <regex>
#include <yaml-cpp/yaml.h>

namespace Voix {

class Config {
public:
    Config();
    ~Config() = default;

    bool load(std::string_view config_path);
    std::vector<Rule> getRules() const;
    std::string getSanctuary() const;
    std::string getPath() const;
    const std::vector<std::string>& getBlocklist() const { return blocklist_; }
    const std::vector<std::regex>& getCompiledBlocklist() const { return compiled_blocklist_; }

private:
    std::string sanctuary_;
    std::vector<std::string> path_list_;
    std::vector<Rule> rules_;
    std::vector<std::string> blocklist_;
    std::vector<std::regex> compiled_blocklist_;
};

} // namespace Voix

#endif // CONFIG_H
