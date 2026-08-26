/**
 * @file permission_checker.hpp
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
 *
 * Rules use first-match semantics: the first rule (in configuration order)
 * that matches the identity, target, command and arguments decides the
 * outcome. A matching DENY rule terminates evaluation with denial.
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
     * @brief Finds a matching rule that permits the execution of a command.
     * @param command The command to check.
     * @param args The arguments for the command.
     * @param target_uid The target user ID.
     * @return The matching Rule if found, otherwise std::nullopt.
     */
    std::optional<Rule> permit(std::string_view command, const std::vector<std::string>& args,
                uid_t target_uid) const;

    /**
     * @brief Returns rules that permit actions for the current user.
     *
     * Mirrors runtime first-match semantics: a PERMIT rule whose scope is
     * already covered by an earlier identity-matching DENY rule (same
     * command, argument pattern and target) is suppressed, because at run
     * time the DENY would win.
     *
     * @return Vector of permitted rules for the current user.
     */
    std::vector<Rule> list_permitted_rules() const;

private:
    std::shared_ptr<Security> security_;
    std::shared_ptr<Config> config_;

    struct MatchPatternParams {
        std::string pattern;
        std::string text;
    };
    /**
     * @brief Internal method to check if a pattern matches a string.
     * @param params Parameters containing the glob-style pattern and the string to check.
     * @return True if matches, false otherwise.
     */
    bool match_pattern(const MatchPatternParams& params) const;

    /**
     * @brief Resolves contextual variables (e.g., %u) in a string.
     * @param text The string to resolve.
     * @return The resolved string.
     */
    std::string resolve_variables(const std::string& text) const;

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
    bool matchRule(const Rule& rule, uid_t uid, const std::vector<gid_t>& groups,
                   std::string_view command, uid_t target_uid,
                   const std::vector<std::string>& args) const;
};

} // namespace Voix

#endif // PERMISSION_CHECKER_H
