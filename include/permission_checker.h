/**
 * @file permission_checker.h
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef PERMISSION_CHECKER_H
#define PERMISSION_CHECKER_H

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <sys/types.h>

namespace Voix {

class Security;
class Config;
class Rule;

class PermissionChecker {
public:
    PermissionChecker(std::shared_ptr<Security> security,
                      std::shared_ptr<Config> config);
    ~PermissionChecker() = default;

    bool isAllowed() const;
    std::optional<Rule> permit(std::string_view command, const std::vector<std::string>& args,
                uid_t target_uid) const;

private:
    std::shared_ptr<Security> security_;
    std::shared_ptr<Config> config_;

    bool matchRule(const Rule& rule, uid_t uid, gid_t* groups, int ngroups,
                   uid_t target_uid, std::string_view command,
                   const std::vector<std::string>& args) const;
};

} // namespace Voix

#endif // PERMISSION_CHECKER_H
