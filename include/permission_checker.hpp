/**
 * @file permission_checker.hpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef PERMISSION_CHECKER_H
#define PERMISSION_CHECKER_H

#include "rule.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <sys/types.h>

namespace Voix {

class Security;
class Config;

/**
 * @brief A permit rule as shown by `voix -l`.
 *
 * `conditional` is set when an earlier DENY rule covers only part of the
 * permit's scope (for example a deny with narrower arguments, or a deny for a
 * single command while the permit matches all commands). Such a permit is
 * still usable, but the listing must not imply that every invocation is
 * allowed.
 */
struct PermittedEntry {
    Rule rule;
    bool conditional = false;
};

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
     * @brief Returns permits for the current user together with deny context.
     *
     * Applies runtime first-match semantics over the whole ordered rule list:
     * a permit fully covered by an earlier identity-matching DENY is omitted,
     * and a permit only partially covered is returned with
     * `conditional = true`.
     *
     * @return Permitted entries for the current user.
     */
    std::vector<PermittedEntry> list_permitted_entries() const;

    /**
     * @brief Returns rules that permit actions for the current user.
     *
     * Compatibility wrapper around list_permitted_entries(). Entries that are
     * only partially restricted are included; callers that want to render the
     * distinction should use list_permitted_entries().
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

    /// A rule's scope with variables resolved and the command canonicalized.
    struct NormalizedRuleScope {
        std::optional<uid_t> target_uid; ///< nullopt = rule can never match.
        std::string command;             ///< Empty means "any command".
        std::vector<std::string> args;   ///< Empty means "any arguments".
        bool pattern = false;            ///< Args are glob patterns.
    };

    /// How much of a permit's scope an earlier deny covers.
    enum class Coverage : std::uint8_t { None, Partial, Full };

    /**
     * @brief Normalizes a rule for scope comparison.
     * @return The normalized scope, or nullopt when the rule can never match
     *         (for example an unresolvable target name).
     */
    std::optional<NormalizedRuleScope> normalize_scope(const Rule& rule) const;

    /**
     * @brief Determines how much of @p permit an earlier @p deny covers.
     */
    Coverage scope_coverage(const NormalizedRuleScope& deny,
                            const NormalizedRuleScope& permit) const;
};

} // namespace Voix

#endif // PERMISSION_CHECKER_H
