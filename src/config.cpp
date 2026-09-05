/**
 * @file config.cpp
 * @brief YAML configuration implementation
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "config.hpp"
#include "file_utils.hpp"
#include "logger.hpp"
#include "rule.hpp"
#include "system_utils.hpp"
#include <cctype>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <numeric>
#include <regex>
#include <string_view>
#include <yaml-cpp/yaml.h>

namespace Voix {

Config::Config()
    : sanctuary_("/tmp"),
      path_list_({"/bin", "/sbin", "/usr/bin", "/usr/sbin"}),
      unconfined_targets_({"root", "alpm"}) {}

namespace {

using IdentitySetter = std::function<void(Voix::Rule &, const std::string &)>;

void parse_acl_section(const YAML::Node &section,
                       const IdentitySetter &set_identity,
                       std::vector<Voix::Rule> &rules);

Voix::Rule parse_rule(const YAML::Node &rule_node) {
  Voix::Rule rule;
  if (rule_node["action"]) {
    rule.action = (rule_node["action"].as<std::string>() == "permit")
                      ? Voix::Rule::Action::PERMIT
                      : Voix::Rule::Action::DENY;
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

  if (rule_node["profile"]) {
    rule.profile = rule_node["profile"].as<std::string>();
  }

  if (rule_node["env"]) {
    for (auto env_entry : rule_node["env"]) {
      std::string env_val = env_entry.as<std::string>();
      const size_t eq = env_val.find('=');
      bool valid = eq != std::string::npos && eq > 0;
      if (valid) {
        const std::string key = env_val.substr(0, eq);
        valid =
            (std::isalpha(static_cast<unsigned char>(key[0])) || key[0] == '_');
        for (size_t i = 1; valid && i < key.size(); ++i) {
          valid =
              std::isalnum(static_cast<unsigned char>(key[i])) || key[i] == '_';
        }
      }
      if (!valid) {
        LOG_ERROR(std::format("Invalid rule env entry '{}': expected KEY=VALUE "
                              "with a C identifier key",
                              env_val));
        throw YAML::Exception(YAML::Mark::null_mark(),
                              "invalid rule env entry: " + env_val);
      }
      rule.envlist.push_back(env_val);
    }
  }

  if (rule_node["target"]) {
    rule.target = rule_node["target"].as<std::string>();
    rule.target_uid = Voix::SystemUtils::getUidByName(rule.target);
    if (!rule.target_uid.has_value()) {
      LOG_ERROR(std::format("Target user '{}' not found", rule.target));
    }
  }

  if (rule_node["command"]) {
    rule.cmd = rule_node["command"].as<std::string>();
  }

  if (rule_node["args"]) {
    for (auto arg : rule_node["args"]) {
      std::string arg_val = arg.as<std::string>();
      rule.cmdargs.push_back(arg_val);
      if (arg_val.find('*') != std::string::npos ||
          arg_val.find('?') != std::string::npos) {
        rule.options |= Voix::Rule::PATTERN;
      }
    }
  }
  return rule;
}

void parse_acl_section(const YAML::Node &section,
                       const IdentitySetter &set_identity,
                       std::vector<Voix::Rule> &rules) {
  for (auto it = section.begin(); it != section.end(); ++it) {
    std::string name = it->first.as<std::string>();
    for (auto rule_node : it->second) {
      // NOTE: a rule's `profile:` key references a *security*
      // profile (security.profiles) and is resolved at execution
      // time by Command::resolve_profile(). It must not be
      // conflated with any other namespace.
      Voix::Rule rule = parse_rule(rule_node);
      set_identity(rule, name);
      rules.push_back(std::move(rule));
    }
  }
}
} // namespace

bool Config::load(std::string_view config_path, bool verify_security) {
  std::string path_str{config_path};
  FileUtils file_utils;
  Logger logger;

  if (!file_utils.fileExists(path_str)) {
    logger.log("ERROR", std::format("Config file not found: {}", path_str));
    return false;
  }

  if (verify_security) {
    // Reject symlinks early; read_file_secure then re-verifies ownership,
    // permissions and regular-file type on the opened descriptor itself,
    // closing the TOCTOU window entirely.
    std::error_code ec;
    if (std::filesystem::is_symlink(path_str, ec)) {
      logger.log("ERROR", std::format("Config file is a symlink (rejected): {}",
                                      path_str));
      return false;
    }
  }

  try {
    std::string config_content;
    if (verify_security) {
      auto result = file_utils.read_file_secure(path_str);
      if (!result) {
        logger.log(
            "ERROR",
            std::format("Failed to securely read config file: {}", path_str));
        return false;
      }
      config_content = std::move(*result);
    } else {
      auto result = file_utils.readFile(path_str);
      if (!result) {
        logger.log("ERROR",
                   std::format("Failed to read config file: {}", path_str));
        return false;
      }
      config_content = std::move(*result);
    }

    YAML::Node config = YAML::Load(config_content);

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
      if (config["core"]["suppress_stderr"]) {
        suppress_stderr_ = config["core"]["suppress_stderr"].as<bool>();
      }
      if (config["core"]["unconfined_targets"]) {
        unconfined_targets_.clear();
        for (auto user_entry : config["core"]["unconfined_targets"]) {
          unconfined_targets_.push_back(user_entry.as<std::string>());
        }
      } else if (config["core"]["privileged_users"]) {
        // Backwards-compatible alias for unconfined_targets.
        unconfined_targets_.clear();
        for (auto user_entry : config["core"]["privileged_users"]) {
          unconfined_targets_.push_back(user_entry.as<std::string>());
        }
      }
    }

    if (config["acl"]) {
      rules_.clear();
      if (config["acl"]["user"]) {
        parse_acl_section(
            config["acl"]["user"],
            [&logger](Rule &rule, const std::string &name) {
              rule.ident = name;
              rule.ident_uid = SystemUtils::getUidByName(name);
              if (!rule.ident_uid.has_value()) {
                logger.log("ERROR",
                           std::format("ACL user '{}' not found", name));
              }
            },
            rules_);
      }
      if (config["acl"]["group"]) {
        parse_acl_section(
            config["acl"]["group"],
            [&logger](Rule &rule, const std::string &name) {
              rule.ident = ":" + name;
              rule.ident_gid = SystemUtils::getGidByName(name);
              if (!rule.ident_gid.has_value()) {
                logger.log("ERROR",
                           std::format("ACL group '{}' not found", name));
              }
            },
            rules_);
      }
    }

    if (config["security"]) {
      if (config["security"]["profiles"]) {
        for (auto it = config["security"]["profiles"].begin();
             it != config["security"]["profiles"].end(); ++it) {
          std::string profile_name = it->first.as<std::string>();
          YAML::Node p_node = it->second;
          SecurityProfile profile;
          if (p_node["retain_full_capabilities"])
            profile.retain_full_capabilities =
                p_node["retain_full_capabilities"].as<bool>();
          if (p_node["enable_seccomp"])
            profile.enable_seccomp = p_node["enable_seccomp"].as<bool>();
          if (p_node["enable_resource_limits"])
            profile.enable_resource_limits =
                p_node["enable_resource_limits"].as<bool>();
          if (p_node["scrub_environment"])
            profile.scrub_environment = p_node["scrub_environment"].as<bool>();
          if (p_node["preserve_full_environment"])
            profile.preserve_full_environment =
                p_node["preserve_full_environment"].as<bool>();
          if (p_node["seccomp_mode"])
            profile.seccomp_mode = p_node["seccomp_mode"].as<std::string>();
          security_profiles_[profile_name] = profile;
        }
      }
      if (config["security"]["seccomp"]) {
        seccomp_enabled_ = config["security"]["seccomp"].as<bool>();
      }
      if (config["security"]["blocklist"]) {
        for (auto block_item : config["security"]["blocklist"]) {
          if (!block_item.IsScalar())
            continue;
          std::string entry = block_item.as<std::string>();
          constexpr std::string_view k_regex_prefix = "regex:";
          if (entry.starts_with(k_regex_prefix)) {
            std::string pattern = entry.substr(k_regex_prefix.size());
            try {
              regex_blocklist_.emplace_back(
                  pattern, std::regex(pattern, std::regex::optimize));
            } catch (const std::regex_error &e) {
              LOG_ERROR(std::format("Invalid blocklist regex '{}': {}", pattern,
                                    e.what()));
              return false;
            }
          } else {
            blocklist_.push_back(entry);
          }
        }
      }
    }
  } catch (const YAML::Exception &e) {
    logger.log("ERROR",
               std::format("Failed to parse YAML config: {}", e.what()));
    return false;
  }

  return true;
}

const std::vector<Rule> &Config::getRules() const { return rules_; }

std::string Config::getSanctuary() const { return sanctuary_; }

std::string Config::getPath() const {
  if (path_list_.empty())
    return "";
  return std::accumulate(
      std::next(path_list_.begin()), path_list_.end(), path_list_[0],
      [](const std::string &a, const std::string &b) { return a + ":" + b; });
}

bool Config::validate() const {
  // Validate sanctuary path exists and is a directory
  if (sanctuary_.empty()) {
    return false;
  }
  std::error_code ec;
  bool is_dir = std::filesystem::is_directory(sanctuary_, ec);
  if (ec) {
    // Filesystem error (e.g., permission denied, path does not exist)
    return false;
  }
  if (!is_dir) {
    // Path exists but is not a directory
    return false;
  }

  // Validate path_list entries are absolute paths
  for (const auto &p : path_list_) {
    if (p.empty() || p[0] != '/') {
      return false;
    }
  }

  // Validate rules have consistent structure
  for (const auto &rule : rules_) {
    // Each rule must have an identity (user or group)
    if (rule.ident.empty() && !rule.ident_uid.has_value() &&
        !rule.ident_gid.has_value()) {
      return false;
    }
    // If a command is specified with args, args must not be empty strings
    if (!rule.cmd.empty() && !rule.cmdargs.empty()) {
      for (const auto &arg : rule.cmdargs) {
        if (arg.empty()) {
          return false;
        }
      }
    }
  }

  // Validate blocklist entries are non-empty
  for (const auto &entry : blocklist_) {
    if (entry.empty()) {
      return false;
    }
  }

  return true;
}

bool Config::is_unconfined_target(std::string_view user) const {
  return std::ranges::find(unconfined_targets_, user) !=
         unconfined_targets_.end();
}

SecurityProfile Config::get_profile(std::string_view name) const {
  if (security_profiles_.count(std::string(name))) {
    return security_profiles_.at(std::string(name));
  }
  // Default "restricted" profile
  return SecurityProfile{false, true, true, true};
}

} // namespace Voix
