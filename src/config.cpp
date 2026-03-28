/**
 * @file config.cpp
 * @brief Basic configuration implementation (stub)
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "config.h"
#include "rule.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <optional>

namespace Voix {

Config::Config() = default;



bool Config::load(std::string_view config_path) {
    std::string path_str{config_path};
    std::ifstream config_file(path_str);
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

std::vector<Rule> Config::getRules() const {
    return rules_;
}

static std::string_view trim(std::string_view s) {
    s.remove_prefix(std::min(s.find_first_not_of(" \t\r\n"), s.size()));
    s.remove_suffix(s.size() - std::min(s.find_last_not_of(" \t\r\n") + 1, s.size()));
    return s;
}

void Config::parseConfigLine(std::string_view line) {
    line = trim(line);
    if (line.empty() || line[0] == '#') return;

    // Handle global settings (Sanctuary, Path)
    if (line.starts_with("sanctuary:")) {
        // Implementation of global log setting could go here
        return;
    }

    std::stringstream ss{std::string(line)};
    std::string keyword;
    ss >> keyword;

    if (keyword != "ordain" && keyword != "shun") {
        return;
    }

    Rule rule;
    rule.action = (keyword == "ordain") ? Rule::PERMIT : Rule::DENY;

    std::string token;
    while (ss >> token) {
        if (token == "trust") {
            rule.options |= Rule::NOPASS;
        } else if (token == "mask") {
            ss >> rule.target;
        } else if (token == "rite") {
            ss >> rule.cmd;
            std::string arg;
            while (ss >> arg) {
                rule.cmdargs.push_back(arg);
            }
            break; 
        } else {
            // If it's not a keyword, it's the identifier (user/group)
            rule.ident = token;
        }
    }

    if (!rule.ident.empty()) {
        rules_.push_back(std::move(rule));
    }
}

} // namespace Voix
