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
#include "file_utils.hpp"
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>
#include <algorithm>
#include <ranges>
#include <regex>

namespace Voix {

namespace {

/// Canonicalize a command for ACL comparison. A command that cannot be
/// resolved to a safe executable is kept literal so policy tests and rules
/// for non-executable strings retain their exact-match behavior; the
/// execution path independently refuses such commands.
std::string canonical_command_for_match(std::string_view command,
                                        const Config& config) {
  FileUtils file_utils;
  auto resolved = file_utils.resolve_executable(command, config.getPath());
  return resolved ? resolved->policy_path : std::string(command);
}

/// Resolve a rule's target to a concrete UID. An empty target means root (the
/// runtime default). An unresolvable name yields nullopt because matchRule()
/// rejects every invocation for such a rule.
std::optional<uid_t> rule_target_uid(const Rule& rule) {
  if (rule.target_uid.has_value()) {
    return rule.target_uid;
  }
  if (rule.target.empty()) {
    return static_cast<uid_t>(0);
  }
  char* endptr = nullptr;
  const uid_t uid =
      static_cast<uid_t>(strtol(rule.target.c_str(), &endptr, 10));
  if (endptr != rule.target.c_str() && endptr != nullptr && *endptr == '\0') {
    return uid;
  }
  return std::nullopt;
}

/// Mirrors matchRule()'s identity gate for listing.
bool identity_matches(const Rule& rule, uid_t uid,
                      const std::vector<gid_t>& groups) {
  if (rule.ident_uid.has_value()) {
    return rule.ident_uid.value() == uid;
  }
  if (rule.ident_gid.has_value()) {
    return std::ranges::find(groups, rule.ident_gid.value()) != groups.end();
  }
  if (!rule.ident.empty()) {
    if (rule.ident.starts_with('%')) {
      return false;
    }
    char* endptr = nullptr;
    const uid_t rule_uid =
        static_cast<uid_t>(strtol(rule.ident.c_str(), &endptr, 10));
    if (endptr != rule.ident.c_str() && endptr != nullptr && *endptr == '\0') {
      return rule_uid == uid;
    }
    return false;
  }
  // No identity constraint: the rule applies to every caller.
  return true;
}

} // namespace

PermissionChecker::PermissionChecker(std::shared_ptr<Security> security,
                                     std::shared_ptr<Config> config)
    : security_(std::move(security)), config_(std::move(config)) {}

bool PermissionChecker::match_pattern(const MatchPatternParams& params) const {
  const std::string& pattern = params.pattern;
  const std::string& text = params.text;
  std::string regex_pattern = "^";
  for (char c : pattern) {
    if (c == '*') regex_pattern += ".*";
    else if (c == '?') regex_pattern += '.';
    else if (c == '\\' || std::string(".+^$|()[]{}").find(c) != std::string::npos) {
      regex_pattern += '\\';
      regex_pattern += c;
    } else {
      regex_pattern += c;
    }
  }
  regex_pattern += '$';
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
      if (rule.ident.starts_with('%')) {
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
    const std::string requested_cmd =
        canonical_command_for_match(command, *config_);
    resolved_cmd = canonical_command_for_match(resolved_cmd, *config_);
    if (resolved_cmd != requested_cmd)
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


std::optional<PermissionChecker::NormalizedRuleScope>
PermissionChecker::normalize_scope(const Rule& rule) const {
  NormalizedRuleScope scope;
  scope.target_uid = rule_target_uid(rule);
  if (!scope.target_uid.has_value()) {
    return std::nullopt;
  }

  if (!rule.cmd.empty()) {
    scope.command =
        canonical_command_for_match(resolve_variables(rule.cmd), *config_);
  }
  scope.pattern = (rule.options & Rule::PATTERN) != 0;
  scope.args.reserve(rule.cmdargs.size());
  for (const auto& arg : rule.cmdargs) {
    scope.args.push_back(resolve_variables(arg));
  }
  return scope;
}

PermissionChecker::Coverage PermissionChecker::scope_coverage(
    const NormalizedRuleScope& deny, const NormalizedRuleScope& permit) const {
  if (!deny.target_uid.has_value() || !permit.target_uid.has_value() ||
      deny.target_uid.value() != permit.target_uid.value()) {
    return Coverage::None;
  }

  // An empty command/argument list in a rule means "any": matchRule() skips
  // the corresponding comparison entirely.
  if (deny.command.empty()) {
    return Coverage::Full;
  }
  if (permit.command.empty()) {
    return Coverage::Partial;
  }
  if (deny.command != permit.command) {
    return Coverage::None;
  }

  if (deny.args.empty()) {
    return Coverage::Full;
  }
  if (permit.args.empty()) {
    return Coverage::Partial;
  }
  if (deny.args.size() != permit.args.size()) {
    return Coverage::None;
  }

  if (!deny.pattern) {
    // Exact deny arguments only fully cover an exact permit of the same shape.
    if (permit.pattern) {
      return Coverage::Partial;
    }
    return deny.args == permit.args ? Coverage::Full : Coverage::None;
  }

  // The deny uses glob patterns. An exact permit is covered when every
  // argument matches; a patterned permit is only provably covered when the
  // patterns are identical.
  if (permit.pattern) {
    return deny.args == permit.args ? Coverage::Full : Coverage::Partial;
  }
  for (size_t i = 0; i < deny.args.size(); ++i) {
    if (!match_pattern({deny.args[i], permit.args[i]})) {
      return Coverage::None;
    }
  }
  return Coverage::Full;
}

std::vector<PermittedEntry> PermissionChecker::list_permitted_entries() const {
  std::vector<PermittedEntry> permitted;
  std::string current_user = security_->getCurrentUser();
  auto identity = security_->identity->get_user_by_name(current_user);
  if (!identity) return permitted;

  const uid_t uid = identity->uid;
  const std::vector<gid_t> groups = identity->groups;

  // First-match semantics: only DENY rules seen before a permit can suppress
  // or qualify it, so accumulate them in configuration order.
  std::vector<NormalizedRuleScope> denied_scopes;
  for (const auto& rule : config_->getRules()) {
    if (!identity_matches(rule, uid, groups)) {
      continue;
    }

    auto scope = normalize_scope(rule);
    if (!scope.has_value()) {
      // Unresolvable target: the rule can never match at runtime.
      continue;
    }

    if (rule.action == Rule::Action::DENY) {
      denied_scopes.push_back(std::move(*scope));
      continue;
    }

    bool suppressed = false;
    bool conditional = false;
    for (const auto& deny : denied_scopes) {
      switch (scope_coverage(deny, *scope)) {
        case Coverage::Full:
          suppressed = true;
          break;
        case Coverage::Partial:
          conditional = true;
          break;
        case Coverage::None:
          break;
      }
      if (suppressed) {
        break;
      }
    }

    if (!suppressed) {
      permitted.push_back({rule, conditional});
    }
  }
  return permitted;
}

std::vector<Rule> PermissionChecker::list_permitted_rules() const {
  std::vector<Rule> rules;
  for (auto& entry : list_permitted_entries()) {
    rules.push_back(std::move(entry.rule));
  }
  return rules;
}

} // namespace Voix
