/**
 * @file config.cpp
 * @brief YAML configuration implementation
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
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <numeric>
#include <format>

namespace Voix {

Config::Config() : sanctuary_("/tmp"), path_list_({"/bin", "/sbin", "/usr/bin", "/usr/sbin"}) {}

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

    try {
        YAML::Node config = YAML::LoadFile(path_str);

        if (config["globals"]) {
            if (config["globals"]["sanctuary"]) {
                sanctuary_ = config["globals"]["sanctuary"].as<std::string>();
            }
            if (config["globals"]["path"]) {
                path_list_.clear();
                for (auto path_entry : config["globals"]["path"]) {
                    path_list_.push_back(path_entry.as<std::string>());
                }
            }
        }

        if (config["rules"]) {
            rules_.clear();
            for (auto rule_node : config["rules"]) {
                Rule rule;
                if (rule_node["ordain"]) {
                    rule.action = Rule::PERMIT;
                } else if (rule_node["shun"]) {
                    rule.action = Rule::DENY;
                } else if (rule_node["action"]) {
                    rule.action = (rule_node["action"].as<std::string>() == "permit") ? Rule::PERMIT : Rule::DENY;
                }

                if (rule_node["identity"]) {
                    rule.ident = rule_node["identity"].as<std::string>();
                    if (rule.ident.starts_with("%") || rule.ident.starts_with(":")) {
                        rule.ident_gid = SystemUtils::getGidByName(rule.ident.substr(1));
                    } else {
                        rule.ident_uid = SystemUtils::getUidByName(rule.ident);
                    }
                }

                if (rule_node["trust"] && rule_node["trust"].as<bool>()) {
                    rule.options |= Rule::NOPASS;
                }

                if (rule_node["mask"]) {
                    rule.target = rule_node["mask"].as<std::string>();
                    rule.target_uid = SystemUtils::getUidByName(rule.target);
                }

                if (rule_node["command"] || rule_node["rite"]) {
                    rule.cmd = rule_node["command"] ? rule_node["command"].as<std::string>() : rule_node["rite"].as<std::string>();
                }

                if (rule_node["args"]) {
                    for (auto arg : rule_node["args"]) {
                        rule.cmdargs.push_back(arg.as<std::string>());
                    }
                }

                rules_.push_back(std::move(rule));
            }
        }
    } catch (const YAML::Exception& e) {
        logger.log("ERROR", std::format("Failed to parse YAML config: {}", e.what()));
        return false;
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
    if (path_list_.empty()) return "";
    return std::accumulate(std::next(path_list_.begin()), path_list_.end(), path_list_[0],
                           [](std::string a, std::string b) {
                               return a + ":" + b;
                           });
}

} // namespace Voix

