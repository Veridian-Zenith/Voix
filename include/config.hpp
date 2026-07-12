/**
 * @file config.h
 * @brief Configuration management
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "rule.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <regex>
#include <map>
#include <yaml-cpp/yaml.h>

namespace Voix {

struct SecurityProfile {
    bool retain_full_capabilities = false;
    bool enable_seccomp = true;
    bool enable_resource_limits = true;
    bool scrub_environment = true;
    // Preserve the entire inherited environment verbatim, without stripping
    // loader/interpreted-language variables (LD_*, PYTHON*, etc.). Intended
    // only for confined system targets such as the package-manager user.
    bool preserve_full_environment = false;
};

class Config {
public:
    /**
     * @brief Default constructor for Config.
     */
    Config();
    /**
     * @brief Default destructor for Config.
     */
    ~Config() = default;

    /**
     * @brief Loads configuration from a YAML file.
     * @param config_path Path to the configuration file.
     * @param verify_security Whether to verify the security of the configuration file.
     * @return True if the configuration was loaded successfully, false otherwise.
     */
    bool load(std::string_view config_path, bool verify_security = true);
    /**
     * @brief Gets the list of rules from the configuration.
     * @return A vector of Rule objects.
     */
    const std::vector<Rule>& getRules() const;
    /**
     * @brief Gets the sanctuary path from the configuration.
     * @return The sanctuary path as a string.
     */
    std::string getSanctuary() const;
    /**
     * @brief Gets the system path from the configuration.
     * @return The system path as a string.
     */
    std::string getPath() const;
    /**
     * @brief Checks if seccomp is enabled.
     * @return True if enabled, false otherwise.
     */
    bool is_seccomp_enabled() const { return seccomp_enabled_; }
    /**
     * @brief Checks if login shell is default.
     * @return True if default, false otherwise.
     */
    bool is_login_shell_default() const { return login_shell_default_; }
    /**
     * @brief Checks if stderr logging should be suppressed.
     * @return True if suppressed, false otherwise.
     */
    bool should_suppress_stderr() const { return suppress_stderr_; }
    /**
     * @brief Gets the blocklist of commands.
     * @return A reference to the blocklist vector.
     */
    const std::vector<std::string>& get_blocklist() const { return blocklist_; }
    /**
     * @brief Gets the compiled blocklist of regular expressions.
     * @return A reference to the compiled blocklist vector.
     */
    const std::vector<std::regex>& get_compiled_blocklist() const { return compiled_blocklist_; }
    /**
     * @brief Gets the security profile associated with a name.
     * @param name The profile name.
     * @return The SecurityProfile object.
     */
    SecurityProfile get_profile(std::string_view name) const;
    /**
     * @brief Checks if a target is an unconfined system target.
     *
     * Unconfined targets (e.g. the package-manager user) receive the full
     * "system" treatment: retained capabilities, no seccomp, no FD scrubbing,
     * and a fully preserved environment. This is required for package managers
     * such as pacman and is intentionally opt-in per target.
     *
     * @param user The target username to check.
     * @return True if the target is unconfined, false otherwise.
     */
    bool is_unconfined_target(std::string_view user) const;
    /**
     * @brief Gets the list of unconfined system targets.
     * @return A reference to the unconfined targets vector.
     */
    const std::vector<std::string>& get_unconfined_targets() const { return unconfined_targets_; }
    /**
     * @brief Validates the configuration schema and path permissions.
     * @return True if valid, false otherwise.
     */
    bool validate() const;

private:
    std::string sanctuary_;
    std::vector<std::string> path_list_;
    std::vector<Rule> rules_;
    std::map<std::string, std::vector<Rule>> profiles_;
    std::map<std::string, SecurityProfile> security_profiles_;
    std::vector<std::string> blocklist_;
    std::vector<std::regex> compiled_blocklist_;
    std::vector<std::string> unconfined_targets_;
    bool seccomp_enabled_ = true;
    bool login_shell_default_ = false;
    bool suppress_stderr_ = true;
};

} // namespace Voix

#endif // CONFIG_H
