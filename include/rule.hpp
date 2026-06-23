/**
 * @file rule.h
 * @brief Rule definition for Voix
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef RULE_H
#define RULE_H

#include <string>
#include <vector>
#include <optional>
#include <sys/types.h>
#include <cstdint>

namespace Voix {

/**
 * @brief Represents a security rule for command execution.
 */
class Rule {
public:
    /**
     * @brief Action to take when a rule matches.
     */
    enum class Action : std::uint8_t { PERMIT, DENY };
    /**
     * @brief Options that modify the rule's behavior.
     */
    enum Option : std::uint8_t {
        NOPASS = 0x1,   /**< Do not request password for this rule. */
        KEEPENV = 0x2,  /**< Preserve environment variables. */
        PERSIST = 0x4,  /**< Persist the session. */
        NOLOG = 0x8,     /**< Do not log this execution. */
        PATTERN = 0x10   /**< Use pattern matching for command arguments. */
    };

    std::string ident;                 /**< Identifier for the rule. */
    std::optional<uid_t> ident_uid;    /**< Optional UID for the identity. */
    std::optional<gid_t> ident_gid;    /**< Optional GID for the identity. */

    std::string target;                /**< Target identity for the command. */
    std::optional<uid_t> target_uid;   /**< Optional UID for the target. */

    std::string cmd;                   /**< The command to execute. */
    std::vector<std::string> cmdargs;  /**< Arguments for the command. */
    std::vector<std::string> envlist;  /**< Environment variables to set. */
    std::string profile;                  /**< Security profile to apply. */
    Action action;                     /**< Action to take on match. */
    int options;                       /**< Combined options flags. */

    /**
     * @brief Default constructor for Rule.
     */
    Rule() : action(Action::PERMIT), options(0) {}
};

} // namespace Voix

#endif // RULE_H
