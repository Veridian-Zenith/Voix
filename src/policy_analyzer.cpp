#include "policy_analyzer.hpp"
#include <algorithm>
#include <format>

namespace Voix {

PolicyAnalyzer::PolicyAnalyzer(const Config& config) : config_(config) {}

std::vector<PolicyFinding> PolicyAnalyzer::analyze() const {
    std::vector<PolicyFinding> findings;
    check_empty_acl(findings);
    check_unconfined_targets(findings);
    check_redundant_rules(findings);
    check_open_permissions(findings);
    check_referenced_profiles(findings);
    check_blocklist_coverage(findings);
    return findings;
}

void PolicyAnalyzer::check_empty_acl(std::vector<PolicyFinding>& findings) const {
    if (config_.getRules().empty()) {
        findings.push_back({
            PolicyFinding::Severity::WARNING,
            "No ACL rules defined. All commands will be denied."
        });
    }
}

void PolicyAnalyzer::check_unconfined_targets(std::vector<PolicyFinding>& findings) const {
    const auto& targets = config_.get_unconfined_targets();
    for (const auto& target : targets) {
        if (target == "root") {
            findings.push_back({
                PolicyFinding::Severity::WARNING,
                "root is an unconfined target — retains full capabilities, "
                "no seccomp, no FD scrubbing, full environment. Remove root "
                "from unconfined_targets to confine generic root commands."
            });
        }
    }
}

void PolicyAnalyzer::check_redundant_rules(std::vector<PolicyFinding>& findings) const {
    const auto& rules = config_.getRules();
    for (size_t i = 0; i < rules.size(); ++i) {
        for (size_t j = i + 1; j < rules.size(); ++j) {
            if (rules[i].ident == rules[j].ident &&
                rules[i].cmd == rules[j].cmd &&
                rules[i].action == rules[j].action &&
                rules[i].target == rules[j].target) {
                findings.push_back({
                    PolicyFinding::Severity::WARNING,
                    std::format("Redundant rules at positions {} and {} "
                                "(same identity, command, action, target)",
                                i + 1, j + 1)
                });
            }
        }
    }
}

void PolicyAnalyzer::check_open_permissions(std::vector<PolicyFinding>& findings) const {
    const auto& rules = config_.getRules();
    for (const auto& rule : rules) {
        if (rule.action == Rule::Action::PERMIT && rule.cmd.empty()) {
            findings.push_back({
                PolicyFinding::Severity::WARNING,
                std::format("Rule for '{}' permits ALL commands without restriction. "
                            "Consider specifying allowed commands.",
                            rule.ident)
            });
        }
    }
}

void PolicyAnalyzer::check_referenced_profiles(std::vector<PolicyFinding>& /* findings */) const {
    // Reserved for future use: detect rules referencing non-existent profiles.
}

void PolicyAnalyzer::check_blocklist_coverage(std::vector<PolicyFinding>& findings) const {
    const auto& blocklist = config_.get_blocklist();
    if (blocklist.empty()) {
        findings.push_back({
            PolicyFinding::Severity::WARNING,
            "No blocklist defined. Consider adding entries for dangerous "
            "commands (e.g., /bin/sh, /bin/bash)."
        });
    }
}

} // namespace Voix
