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

namespace Voix {

class Config {
public:
    Config();
    ~Config() = default;

    bool load(std::string_view config_path);
    std::vector<Rule> getRules() const;
    std::string getSanctuary() const;
    std::string getPath() const;

private:
    std::string sanctuary_;
    std::string path_;
    std::string file_content_;
    std::vector<std::string> processed_tokens_;
    std::vector<Rule> rules_;
    void parseConfigLine(std::string_view line);
};

} // namespace Voix

#endif // CONFIG_H
