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

#include <string_view>
#include <vector>
#include <optional>
#include <sys/types.h>
#include <cstdint>

namespace Voix {

class Rule {
public:
    enum Action : uint8_t { PERMIT, DENY };
    enum Option : uint8_t {
        NOPASS = 0x1,
        KEEPENV = 0x2,
        PERSIST = 0x4,
        NOLOG = 0x8
    };

    std::string_view ident;
    std::optional<uid_t> ident_uid;
    std::optional<gid_t> ident_gid;

    std::string_view target;
    std::optional<uid_t> target_uid;

    std::string_view cmd;
    std::vector<std::string_view> cmdargs;
    std::vector<std::string_view> envlist;
    Action action;
    int options;

    Rule() : action(PERMIT), options(0) {}
};

} // namespace Voix

#endif // RULE_H
