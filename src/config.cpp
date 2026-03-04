/**
 * @file config.cpp
 * @brief Basic configuration implementation (stub)
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include "config.h"
#include "rule.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <optional>

namespace Voix {

Config::Config() = default;



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

std::vector<Rule> Config::getRules() const {
    return rules_;
}

void Config::parseConfigLine(const std::string& line) {
    std::stringstream ss(line);
    std::string keyword;
    ss >> keyword;

    if (keyword != "permit" && keyword != "deny") {
        return;
    }

    Rule rule;
    rule.action = (keyword == "permit") ? Rule::PERMIT : Rule::DENY;

    std::string token;
    ss >> token;

    if (token == "nopass") {
        rule.options |= Rule::NOPASS;
        ss >> token;
    }

    rule.ident = token;

    while (ss >> token) {
        if (token == "as") {
            ss >> rule.target;
        } else if (token == "cmd") {
            ss >> rule.cmd;
            std::string arg;
            while(ss >> arg) {
                rule.cmdargs.push_back(arg);
            }
            break;
        }
    }
    rules_.push_back(rule);
}

} // namespace Voix
