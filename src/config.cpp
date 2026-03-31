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
#include "system_utils.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <optional>
#include <cctype>

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

    if (line.starts_with("sanctuary:")) {
        // Implementation of global log setting could go here
        return;
    }

    std::vector<std::string> tokens;
    std::string current;
    bool in_quotes = false;
    bool escaped = false;
    for (char c : line) {
        if (escaped) {
            current += c;
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else if (c == '"') {
            in_quotes = !in_quotes;
        } else if (std::isspace(static_cast<unsigned char>(c)) && !in_quotes) {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }
    if (!current.empty()) {
        tokens.push_back(current);
    }

    if (tokens.empty()) return;

    const std::string& keyword = tokens[0];
    if (keyword != "ordain" && keyword != "shun") {
        return;
    }

    Rule rule;
    rule.action = (keyword == "ordain") ? Rule::PERMIT : Rule::DENY;

    for (size_t i = 1; i < tokens.size(); ++i) {
        const std::string& token = tokens[i];
        if (token == "trust") {
            rule.options |= Rule::NOPASS;
        } else if (token == "mask") {
            if (i + 1 < tokens.size()) {
                rule.target = tokens[++i];
                rule.target_uid = SystemUtils::getUidByName(rule.target);
            }
        } else if (token == "rite") {
            if (i + 1 < tokens.size()) {
                rule.cmd = tokens[++i];
                for (size_t j = i + 1; j < tokens.size(); ++j) {
                    rule.cmdargs.push_back(tokens[j]);
                }
            }
            break;
        } else {
            rule.ident = token;
            if (rule.ident.starts_with("%")) {
                rule.ident_gid = SystemUtils::getGidByName(rule.ident.substr(1));
            } else {
                rule.ident_uid = SystemUtils::getUidByName(rule.ident);
            }
        }
    }

    if (!rule.ident.empty()) {
        rules_.push_back(std::move(rule));
    }
}

} // namespace Voix

