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

namespace Voix {

class Rule {
public:
    enum Action { PERMIT, DENY };
    enum Option {
        NOPASS = 0x1,
        KEEPENV = 0x2,
        PERSIST = 0x4,
        NOLOG = 0x8
    };

    std::string ident;
    std::optional<uid_t> ident_uid;
    std::optional<gid_t> ident_gid;

    std::string target;
    std::optional<uid_t> target_uid;

    std::string cmd;
    std::vector<std::string> cmdargs;
    std::vector<std::string> envlist;
    Action action;
    int options;

    Rule() : action(PERMIT), options(0) {}
};

} // namespace Voix

#endif // RULE_H
