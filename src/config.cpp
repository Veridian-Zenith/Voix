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
#include "file_utils.h"
#include "logger.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <optional>
#include <cctype>
#include <format>

namespace Voix {

Config::Config() : sanctuary_("/bin"), path_("/usr/bin") {}

bool Config::load(std::string_view config_path) {
    std::string path_str{config_path};
    FileUtils file_utils;
    Logger logger;

    if (!file_utils.fileExists(path_str)) {
        logger.log("ERROR", std::format("Config file not found: {}", path_str));
        return false;
    }

    if (!file_utils.isSecurePath(path_str)) {
        logger.log("ERROR", std::format("Config file security check failed: {}", path_str));
        return false;
    }

    std::ifstream config_file(path_str);
    if (!config_file.is_open()) {
        return false;
    }

    std::stringstream buffer;
    buffer << config_file.rdbuf();
    file_content_ = buffer.str();
    config_file.close();

    std::string_view content_view = file_content_;
    size_t pos = 0;
    while (pos < content_view.size()) {
        auto next_nl = content_view.find('\n', pos);
        if (next_nl == std::string_view::npos) {
            next_nl = content_view.size();
        }
        std::string_view line = content_view.substr(pos, next_nl - pos);
        parseConfigLine(line);
        pos = next_nl + 1;
    }

    return true;
}

std::vector<Rule> Config::getRules() const {
    return rules_;
}

std::string Config::getSanctuary() const {
    return sanctuary_;
}

std::string Config::getPath() const {
    return path_;
}

static std::string_view trim(std::string_view s) {
    s.remove_prefix(std::min(s.find_first_not_of(" \t\r\n"), s.size()));
    auto last = s.find_last_not_of(" \t\r\n");
    if (last == std::string_view::npos) {
        return {};
    }
    s.remove_suffix(s.size() - last - 1);
    return s;
}

static std::string unescape_and_unquote(std::string_view token) {
    std::string result;
    bool in_quotes = token.starts_with('"') && token.ends_with('"');
    if (in_quotes) {
        token.remove_prefix(1);
        token.remove_suffix(1);
    }

    result.reserve(token.length());
    bool escaped = false;
    for (char c : token) {
        if (escaped) {
            result += c;
            escaped = false;
        } else if (c == '\\') {
            escaped = true;
        } else {
            result += c;
        }
    }
    return result;
}

void Config::parseConfigLine(std::string_view line) {
    line = trim(line);
    if (line.empty() || line[0] == '#') return;

    if (line.starts_with("sanctuary")) {
        auto value = trim(line.substr(10));
        sanctuary_ = unescape_and_unquote(value);
        return;
    } else if (line.starts_with("path")) {
        auto value = trim(line.substr(5));
        path_ = unescape_and_unquote(value);
        return;
    }

    std::vector<std::string_view> tokens;
    size_t start = 0;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '\\') {
            i++;
            continue;
        }
        if (line[i] == '"') {
            in_quotes = !in_quotes;
        } else if (!in_quotes && std::isspace(static_cast<unsigned char>(line[i]))) {
            if (i > start) {
                tokens.push_back(line.substr(start, i - start));
            }
            start = i + 1;
            while(start < line.size() && std::isspace(static_cast<unsigned char>(line[start]))) {
                start++;
            }
            i = start - 1;
        }
    }
    if (start < line.size()) {
        tokens.push_back(line.substr(start));
    }

    if (tokens.empty()) return;

    for(auto& token : tokens) {
        bool is_quoted = token.starts_with('"') && token.ends_with('"');
        bool has_escape = false;
        for(size_t i = 0; i < token.size(); ++i) {
            if (token[i] == '\\') {
                has_escape = true;
                i++;
            }
        }

        if(is_quoted || has_escape) {
             processed_tokens_.push_back(unescape_and_unquote(token));
             token = processed_tokens_.back();
        }
    }

    const std::string_view& keyword = tokens[0];
    if (keyword != "ordain" && keyword != "shun") {
        return;
    }

    Rule rule;
    rule.action = (keyword == "ordain") ? Rule::PERMIT : Rule::DENY;

    for (size_t i = 1; i < tokens.size(); ++i) {
        const std::string_view& token = tokens[i];
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
            if (rule.ident.starts_with("%") || rule.ident.starts_with(":")) {
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

