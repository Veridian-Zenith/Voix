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
  for (const auto& rule : rules) {
    if (rule.action == Rule::PERMIT && rule.ident == current_user) {
      return true;
    }
  }

  return false;
}
bool PermissionChecker::matchRule(const Rule &rule, uid_t uid, gid_t *groups, int ngroups,
                                    uid_t target_uid, std::string_view command,
                                    const std::vector<std::string> &args) const {
  if (rule.ident_uid.has_value()) {
      if (rule.ident_uid.value() != uid) {
          return false;
      }
  } else if (rule.ident_gid.has_value()) {
      bool group_found = false;
      for (int i = 0; i < ngroups; i++) {
          if (rule.ident_gid.value() == groups[i]) {
              group_found = true;
              break;
          }
      }
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

      for (size_t i = 0; i < args.size(); i++) {
        if (rule.cmdargs[i] != args[i])
          return false;
      }
    }
  }

  return true;
}

std::optional<Rule> PermissionChecker::permit(std::string_view command,
                                 const std::vector<std::string> &args,
                                 uid_t target_uid) const {
  std::string current_user = security_->getCurrentUser();
  struct passwd pwd;
  struct passwd *result = nullptr;
  long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (bufsize == -1) bufsize = 16384;
  std::vector<char> buffer(bufsize);

  if (getpwnam_r(current_user.c_str(), &pwd, buffer.data(), bufsize, &result) != 0 || result == nullptr)
    return std::nullopt;

  uid_t uid = result->pw_uid;
  gid_t groups[NGROUPS_MAX + 1];
  int ngroups = getgroups(NGROUPS_MAX, groups);
  if (ngroups == -1)
    return std::nullopt;
  groups[ngroups++] = getgid();

  auto rules = config_->getRules();

  for (const auto &rule : rules) {
    if (matchRule(rule, uid, groups, ngroups, target_uid, command, args)) {
      if (rule.action == Rule::PERMIT) {
        return rule;
      } else {
        return std::nullopt;
      }
    }
  }

  return std::nullopt;
}

} // namespace Voix
