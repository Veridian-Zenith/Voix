/**
 * @file rule.h
 * @brief Rule definition for Voix
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef RULE_H
#define RULE_H

#include <string>
#include <vector>

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
    std::string target;
    std::string cmd;
    std::vector<std::string> cmdargs;
    std::vector<std::string> envlist;
    Action action;
    int options;

    Rule() : action(PERMIT), options(0) {}
};

} // namespace Voix

#endif // RULE_H
