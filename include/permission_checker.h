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

/**
 * @brief Handles permission checks for command execution based on rules.
 */
class PermissionChecker {
public:
    /**
     * @brief Constructor for PermissionChecker.
     * @param security Pointer to the security manager.
     * @param config Pointer to the configuration manager.
     */
    PermissionChecker(std::shared_ptr<Security> security,
                      std::shared_ptr<Config> config);
    /**
     * @brief Default destructor for PermissionChecker.
     */
    ~PermissionChecker() = default;

    /**
     * @brief Checks if the current action is allowed based on the configuration.
     * @return True if allowed, false otherwise.
     */
    bool isAllowed() const;
    /**
     * @brief Finds a matching rule that permits the execution of a command.
     * @param command The command to check.
     * @param args The arguments for the command.
     * @param target_uid The target user ID.
     * @return The matching Rule if found, otherwise std::nullopt.
     */
    std::optional<Rule> permit(std::string_view command, const std::vector<std::string>& args,
                uid_t target_uid) const;

private:
    std::shared_ptr<Security> security_;
    std::shared_ptr<Config> config_;

    /**
     * @brief Internal method to check if a specific rule matches the given context.
     * @param rule The rule to check.
     * @param uid The user ID of the actor.
     * @param groups The groups of the actor.
     * @param ngroups Number of groups of the actor.
     * @param command The command being executed.
     * @param target_uid The target user ID.
     * @param args The arguments for the command.
     * @return True if the rule matches, false otherwise.
     */
    bool matchRule(const Rule& rule, uid_t uid, gid_t* groups, int ngroups,
                   std::string_view command, uid_t target_uid,
                   const std::vector<std::string>& args) const;
};

} // namespace Voix

#endif // PERMISSION_CHECKER_H
