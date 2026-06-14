/**
 * @file permission_checker.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "permission_checker.hpp"
#include "security.hpp"
#include "config.hpp"
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <cstring>
#include <utility>
#include <vector>
#include <algorithm>
#include <ranges>
#include <regex>
#include <span>

#ifndef NGROUPS_MAX
#define NGROUPS_MAX 32
#endif

namespace Voix {

PermissionChecker::PermissionChecker(std::shared_ptr<Security> security,
                                     std::shared_ptr<Config> config)
    : security_(std::move(security)), config_(std::move(config)) {}

bool PermissionChecker::isAllowed() const {
  std::string current_user = security_->getCurrentUser();

  if (!security_->validateUser(current_user)) {
    return false;
  }

  // A user is allowed if there is at least one permit rule for them.
  auto rules = config_->getRules();
  return std::ranges::any_of(rules, [&](const auto& rule) {
    return rule.action == Rule::Action::PERMIT && rule.ident == current_user;
  });
}
bool PermissionChecker::match_pattern(const MatchPatternParams& params) const {
  const std::string& pattern = params.pattern;
  const std::string& text = params.text;
  std::string regex_pattern = "^";
  for (char c : pattern) {
    if (c == '*') regex_pattern += ".*";
    else if (c == '?') regex_pattern += ".";
    else if (std::string(".+^$|()[]{}").find(c) != std::string::npos) {
      regex_pattern += "\\";
      regex_pattern += c;
    } else {
      regex_pattern += c;
    }
  }
  regex_pattern += "$";
  return std::regex_match(text, std::regex(regex_pattern));
}

std::string PermissionChecker::resolve_variables(const std::string& text) const {
  std::string resolved = text;
  std::string user = security_->getCurrentUser();
  size_t pos = 0;
  while ((pos = resolved.find("%u", pos)) != std::string::npos) {
    resolved.replace(pos, 2, user);
    pos += user.length();
  }
  return resolved;
}

bool PermissionChecker::matchRule(const Rule &rule, uid_t uid, gid_t *groups, int ngroups,
                                    std::string_view command, uid_t target_uid,
                                    const std::vector<std::string> &args) const {
  if (rule.ident_uid.has_value()) {
      if (rule.ident_uid.value() != uid) {
          return false;
      }
  } else if (rule.ident_gid.has_value()) {
      bool group_found = std::ranges::find(std::span(groups, ngroups), rule.ident_gid.value()) != std::span(groups, ngroups).end();
      if (!group_found) {
          return false;
      }
  } else if (!rule.ident.empty()) {
      // Fallback for cases where resolution failed or for special identifiers
      // If it starts with %, it's a group that wasn't found
      if (rule.ident.starts_with("%")) {
          return false;
      }
      // Otherwise try numeric UID match if it's a number
      char* endptr;
      uid_t rule_uid = static_cast<uid_t>(strtol(std::string(rule.ident).c_str(), &endptr, 10));
      if (*endptr == '\0') {
          if (rule_uid != uid) {
              return false;
          }
      } else {
          // It was a name that couldn't be resolved at config load time
          return false;
      }
  }

  if (rule.target_uid.has_value()) {
      if (rule.target_uid.value() != target_uid) {
          return false;
      }
  } else if (!rule.target.empty()) {
      char* endptr;
      uid_t rule_uid = static_cast<uid_t>(strtol(std::string(rule.target).c_str(), &endptr, 10));
      if (*endptr == '\0') {
          if (rule_uid != target_uid) {
              return false;
          }
      } else {
          return false;
      }
  }

  if (!rule.cmd.empty()) {
    std::string resolved_cmd = resolve_variables(rule.cmd);
    if (resolved_cmd != command)
      return false;

    if (!rule.cmdargs.empty()) {
      if (args.size() != rule.cmdargs.size())
        return false;

      if (rule.options & Rule::PATTERN) {
        for (size_t i = 0; i < args.size(); ++i) {
            if (!match_pattern({resolve_variables(rule.cmdargs[i]), args[i]}))
            return false;
        }
      } else {
        for (size_t i = 0; i < args.size(); ++i) {
          if (resolve_variables(rule.cmdargs[i]) != args[i])
            return false;
        }
      }
    }
  }

  return true;
}

std::optional<Rule> PermissionChecker::permit(std::string_view command,
                                  const std::vector<std::string> &args,
                                  uid_t target_uid) const {
  std::string current_user = security_->getCurrentUser();
    auto identity = security_->identity->get_user_by_name(current_user);
  if (!identity) return std::nullopt;

  uid_t uid = identity->uid;
  std::vector<gid_t> groups = identity->groups;
  groups.push_back(identity->gid);
  int ngroups = static_cast<int>(groups.size());
  
  auto rules = config_->getRules();
  
  for (const auto &rule : rules) {
    if (matchRule(rule, uid, groups.data(), ngroups, command, target_uid, args)) {
      if (rule.action == Rule::Action::PERMIT) {
        return rule;
      } else {
        return std::nullopt;
      }
    }
  }
  
  return std::nullopt;
}


} // namespace Voix
