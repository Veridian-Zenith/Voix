/**
 * @file policy_analyzer.hpp
 * @brief Semantic policy analysis for --check-config.
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#pragma once

#include "config.hpp"
#include <string>
#include <vector>

namespace Voix {

struct PolicyFinding {
    enum class Severity : std::uint8_t { WARNING, ERROR };
    Severity severity;
    std::string message;
};

class PolicyAnalyzer {
public:
    explicit PolicyAnalyzer(const Config& config);

    std::vector<PolicyFinding> analyze() const;

private:
    const Config& config_;

    void check_empty_acl(std::vector<PolicyFinding>& findings) const;
    void check_unconfined_targets(std::vector<PolicyFinding>& findings) const;
    void check_redundant_rules(std::vector<PolicyFinding>& findings) const;
    void check_open_permissions(std::vector<PolicyFinding>& findings) const;
    void check_referenced_profiles(std::vector<PolicyFinding>& findings) const;
    void check_blocklist_coverage(std::vector<PolicyFinding>& findings) const;
};

} // namespace Voix
