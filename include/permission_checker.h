#ifndef PERMISSION_CHECKER_H
#define PERMISSION_CHECKER_H

#include <memory>
#include <optional>
#include <string>
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
    std::optional<Rule> permit(const std::string& command, const std::vector<std::string>& args,
                uid_t target_uid) const;

private:
    std::shared_ptr<Security> security_;
    std::shared_ptr<Config> config_;

    bool matchRule(const Rule& rule, uid_t uid, gid_t* groups, int ngroups,
                   uid_t target_uid, const std::string& command,
                   const std::vector<std::string>& args) const;
};

} // namespace Voix

#endif // PERMISSION_CHECKER_H
