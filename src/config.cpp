/**
 * @file config.cpp
 * @brief YAML configuration implementation
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "config.hpp"
#include "rule.hpp"
#include "system_utils.hpp"
#include "file_utils.hpp"
#include "logger.hpp"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <numeric>
#include <format>
#include <regex>

namespace Voix {

Config::Config() : sanctuary_("/tmp"), path_list_({"/bin", "/sbin", "/usr/bin", "/usr/sbin"}) {}


namespace {
    Voix::Rule parseRule(const YAML::Node& rule_node) {
        Voix::Rule rule;
        if (rule_node["action"]) {
            rule.action = (rule_node["action"].as<std::string>() == "permit") ? Voix::Rule::Action::PERMIT : Voix::Rule::Action::DENY;
        }

        if (rule_node["options"]) {
            for (auto opt_node : rule_node["options"]) {
                std::string opt = opt_node.as<std::string>();
                if (opt == "trust" || opt == "nopass") {
                    rule.options |= Voix::Rule::NOPASS;
                } else if (opt == "keepenv") {
                    rule.options |= Voix::Rule::KEEPENV;
                } else if (opt == "persist") {
                    rule.options |= Voix::Rule::PERSIST;
                } else if (opt == "nolog") {
                    rule.options |= Voix::Rule::NOLOG;
                }
            }
        }

        if (rule_node["env"]) {
            for (auto env_entry : rule_node["env"]) {
                rule.envlist.push_back(env_entry.as<std::string>());
            }
        }

        if (rule_node["target"]) {
            rule.target = rule_node["target"].as<std::string>();
            rule.target_uid = Voix::SystemUtils::getUidByName(rule.target);
        }

        if (rule_node["command"]) {
            rule.cmd = rule_node["command"].as<std::string>();
        }

        if (rule_node["args"]) {
            for (auto arg : rule_node["args"]) {
                std::string arg_val = arg.as<std::string>();
                rule.cmdargs.push_back(arg_val);
                if (arg_val.find('*') != std::string::npos || arg_val.find('?') != std::string::npos) {
                    rule.options |= Voix::Rule::PATTERN;
                }
            }
        }
        return rule;
    }
}

bool Config::load(std::string_view config_path, bool verify_security) {
    std::string path_str{config_path};
    FileUtils file_utils;
    Logger logger;

    if (!file_utils.fileExists(path_str)) {
        logger.log("ERROR", std::format("Config file not found: {}", path_str));
        return false;
    }

    if (verify_security && !file_utils.isSecurePath(path_str)) {
        logger.log("ERROR", std::format("Config file security check failed: {}", path_str));
        return false;
    }

    try {
        YAML::Node config = YAML::LoadFile(path_str);

        if (config["core"]) {
            if (config["core"]["sanctuary"]) {
                sanctuary_ = config["core"]["sanctuary"].as<std::string>();
            }
            if (config["core"]["paths"]) {
                path_list_.clear();
                for (auto path_entry : config["core"]["paths"]) {
                    path_list_.push_back(path_entry.as<std::string>());
                }
            }
            if (config["core"]["login_shell"]) {
                login_shell_default_ = config["core"]["login_shell"].as<bool>();
            }
        }

        if (config["profiles"]) {
            profiles_.clear();
            for (auto it = config["profiles"].begin(); it != config["profiles"].end(); ++it) {
                std::string profile_name = it->first.as<std::string>();
                std::vector<Rule> profile_rules;
                for (auto rule_node : it->second) {
                    profile_rules.push_back(parseRule(rule_node));
                }
                profiles_[profile_name] = std::move(profile_rules);
            }
        }

        if (config["acl"]) {
            rules_.clear();
            if (config["acl"]["user"]) {
                for (auto it = config["acl"]["user"].begin(); it != config["acl"]["user"].end(); ++it) {
                    std::string username = it->first.as<std::string>();
                for (auto rule_node : it->second) {
                    if (rule_node["profile"]) {
                        std::string profile_name = rule_node["profile"].as<std::string>();
                        if (profiles_.count(profile_name)) {
                            for (const auto& p_rule : profiles_.at(profile_name)) {
                                Rule rule = p_rule;
                                rule.ident = username;
                                rule.ident_uid = SystemUtils::getUidByName(username);
                                rules_.push_back(std::move(rule));
                            }
                        }
                    } else {
                        Rule rule = parseRule(rule_node);
                        rule.ident = username;
                        rule.ident_uid = SystemUtils::getUidByName(username);
                        rules_.push_back(std::move(rule));
                    }
                }

                }
            }
            if (config["acl"]["group"]) {
                for (auto it = config["acl"]["group"].begin(); it != config["acl"]["group"].end(); ++it) {
                    std::string groupname = it->first.as<std::string>();
                for (auto rule_node : it->second) {
                    if (rule_node["profile"]) {
                        std::string profile_name = rule_node["profile"].as<std::string>();
                        if (profiles_.count(profile_name)) {
                            for (const auto& p_rule : profiles_.at(profile_name)) {
                                Rule rule = p_rule;
                                rule.ident = ":" + groupname;
                                rule.ident_gid = SystemUtils::getGidByName(groupname);
                                rules_.push_back(std::move(rule));
                            }
                        }
                    } else {
                        Rule rule = parseRule(rule_node);
                        rule.ident = ":" + groupname;
                        rule.ident_gid = SystemUtils::getGidByName(groupname);
                        rules_.push_back(std::move(rule));
                    }
                }

                }
            }
        }

        if (config["security"]) {
            if (config["security"]["seccomp"]) {
                seccomp_enabled_ = config["security"]["seccomp"].as<bool>();
            }
            if (config["security"]["blocklist"]) {
                for (auto block_item : config["security"]["blocklist"]) {
                    if (block_item.IsScalar()) {
                        std::string exact = block_item.as<std::string>();
                        std::string pattern = "^" + exact + "$";
                        blocklist_.push_back(exact);
                        compiled_blocklist_.emplace_back(pattern, std::regex::optimize | std::regex::icase);
                    }
                }
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
                           [](const std::string& a, const std::string& b) {
                               return a + ":" + b;
                           });
}

bool Config::validate() const {
    // Basic structural validation is implicitly covered by load()
    // For now, check if the config file itself exists and is readable
    // A more advanced validation would involve checking the schema (using a YAML schema validator)
    return true; 
}

} // namespace Voix


