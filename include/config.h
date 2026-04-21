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
    bool isSeccompEnabled() const { return seccomp_enabled_; }
    bool isLoginShellDefault() const { return login_shell_default_; }
    const std::vector<std::string>& get_blocklist() const { return blocklist_; }
    const std::vector<std::regex>& get_compiled_blocklist() const { return compiled_blocklist_; }

private:
    std::string sanctuary_;
    std::vector<std::string> path_list_;
    std::vector<Rule> rules_;
    std::vector<std::string> blocklist_;
    std::vector<std::regex> compiled_blocklist_;
    bool seccomp_enabled_ = true;
    bool login_shell_default_ = false;
};

} // namespace Voix

#endif // CONFIG_H
