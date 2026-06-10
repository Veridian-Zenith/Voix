/**
 * @file permission_checker.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "permission_checker.h"
#include "security.h"
#include "config.h"
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <cstring>
#include <utility>
#include <vector>
#include <algorithm>
#include <ranges>
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
    if (rule.cmd != command)
      return false;

    if (!rule.cmdargs.empty()) {
      if (args.size() != rule.cmdargs.size())
        return false;

      if (!std::ranges::equal(args, rule.cmdargs))
        return false;
    }
  }

  return true;
}

std::optional<Rule> PermissionChecker::permit(std::string_view command,
                                  const std::vector<std::string> &args,
                                  uid_t target_uid) const {
  std::string current_user = security_->getCurrentUser();
  auto identity = security_->identity_->getUserByName(current_user);
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
