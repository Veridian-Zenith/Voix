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

namespace Voix {

PermissionChecker::PermissionChecker(std::shared_ptr<Security> security,
                                     std::shared_ptr<Config> config)
    : security_(std::move(security)), config_(std::move(config)) {}

bool PermissionChecker::match_pattern(const MatchPatternParams& params) const {
  const std::string& pattern = params.pattern;
  const std::string& text = params.text;
  std::string regex_pattern = "^";
  for (char c : pattern) {
    if (c == '*') regex_pattern += ".*";
    else if (c == '?') regex_pattern += ".";
    else if (c == '\\' || std::string(".+^$|()[]{}").find(c) != std::string::npos) {
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

bool PermissionChecker::matchRule(const Rule &rule, uid_t uid,
                                  const std::vector<gid_t> &groups,
                                  std::string_view command, uid_t target_uid,
                                  const std::vector<std::string> &args) const {
  if (rule.ident_uid.has_value()) {
      if (rule.ident_uid.value() != uid) {
          return false;
      }
  } else if (rule.ident_gid.has_value()) {
      bool group_found = std::ranges::find(groups, rule.ident_gid.value()) != groups.end();
      if (!group_found) {
          return false;
      }
  } else if (!rule.ident.empty()) {
      // Fallback for cases where resolution failed or for special identifiers
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
  } else {
      // No target specified — rule applies only to root (uid 0).
      // Users must add explicit target rules for non-root user switching.
      if (target_uid != 0) {
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

  auto rules = config_->getRules();

  for (const auto &rule : rules) {
    if (matchRule(rule, uid, groups, command, target_uid, args)) {
      if (rule.action == Rule::Action::PERMIT) {
        return rule;
      } else {
        return std::nullopt;
      }
    }
  }

  return std::nullopt;
}


std::vector<Rule> PermissionChecker::list_permitted_rules() const {
    std::vector<Rule> permitted;
    std::string current_user = security_->getCurrentUser();
    auto identity = security_->identity->get_user_by_name(current_user);
    if (!identity) return permitted;

    uid_t uid = identity->uid;
    std::vector<gid_t> groups = identity->groups;

    struct RuleScope {
        std::string cmd;
        std::vector<std::string> cmdargs;
        std::optional<uid_t> target_uid;
    };
    auto scope_of = [](const Rule& r) -> RuleScope {
        return {r.cmd, r.cmdargs, r.target_uid};
    };
    auto scope_equal = [](const RuleScope& a, const RuleScope& b) {
        return a.cmd == b.cmd && a.cmdargs == b.cmdargs &&
               a.target_uid == b.target_uid;
    };

    std::vector<RuleScope> denied_scopes;
    auto rules = config_->getRules();
    for (const auto& rule : rules) {
        // Identity match mirrors matchRule().
        bool identity_match = false;
        if (rule.ident_uid.has_value()) {
            identity_match = (rule.ident_uid.value() == uid);
        } else if (rule.ident_gid.has_value()) {
            identity_match = std::ranges::find(groups, rule.ident_gid.value()) != groups.end();
        } else if (!rule.ident.empty() && !rule.ident.starts_with("%")) {
            char* endptr;
            uid_t rule_uid = static_cast<uid_t>(strtol(std::string(rule.ident).c_str(), &endptr, 10));
            identity_match = (*endptr == '\0' && rule_uid == uid);
        }

        if (!identity_match) continue;

        if (rule.action == Rule::Action::DENY) {
            // Track denied scopes so later PERMIT rules with identical scope
            // are not advertised (first-match would deny them at runtime).
            denied_scopes.push_back(scope_of(rule));
            continue;
        }

        const auto scope = scope_of(rule);
        bool suppressed = std::any_of(denied_scopes.begin(), denied_scopes.end(),
                                      [&](const RuleScope& d) { return scope_equal(d, scope); });
        if (!suppressed) {
            permitted.push_back(rule);
        }
    }
    return permitted;
}

} // namespace Voix
