#include "permission_checker.h"
#include "security.h"
#include "config.h"
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <cstring>
#include <utility>

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
  if (!rule.ident.empty()) {
    if (rule.ident[0] == ':') {
      gid_t rgid;
      char *endptr;
      rgid = strtol(rule.ident.c_str() + 1, &endptr, 10);
      if (*endptr != '\0') {
        struct group *gr = getgrnam(rule.ident.c_str() + 1);
        if (gr)
          rgid = gr->gr_gid;
      }

      bool group_found = false;
      for (int i = 0; i < ngroups; i++) {
        if (rgid == groups[i]) {
          group_found = true;
          break;
        }
      }
      if (!group_found)
        return false;
    } else {
      struct passwd *pw = getpwnam(rule.ident.c_str());
      if (pw) {
        if (pw->pw_uid != uid)
          return false;
      } else {
        uid_t rule_uid =
            static_cast<uid_t>(strtol(rule.ident.c_str(), nullptr, 10));
        if (rule_uid != uid)
          return false;
      }
    }
  }

  if (!rule.target.empty()) {
    struct passwd *pw = getpwnam(rule.target.c_str());
    if (pw) {
      if (pw->pw_uid != target_uid)
        return false;
    } else {
      uid_t rule_uid =
          static_cast<uid_t>(strtol(rule.target.c_str(), nullptr, 10));
      if (rule_uid != target_uid)
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
  struct passwd *pw = getpwnam(current_user.c_str());
  if (!pw)
    return std::nullopt;

  uid_t uid = pw->pw_uid;
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
