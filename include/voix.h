/**
 * @file voix.h
 * @brief Enhanced Voix header with OpenDoas integration
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#ifndef VOIX_H
#define VOIX_H

#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace Voix {

class Config;
class Security;
class Utils;
class LuaConfig;

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

/**
 * @brief Enhanced Voix class with OpenDoas integration
 */
class Voix {
public:
    Voix(const std::string& config_path = "/etc/voix.conf",
         bool non_interactive = false, bool clear_timestamp = false);
    ~Voix();

    /**
     * @brief Execute a command with elevated privileges
     * @param command Command to execute
     * @param args Command arguments
     * @param user Target user (optional, defaults to root)
     * @return Exit code of the command
     */
    int execute(const std::string& command,
                const std::vector<std::string>& args = {},
                const std::string& user = "root");

    /**
     * @brief Check if current user can use Voix
     * @return true if allowed, false otherwise
     */
    bool isAllowed() const;

    /**
     * @brief Validate command before execution
     * @param command Command to validate
     * @param args Command arguments
     * @return true if valid, false otherwise
     */
    bool validateCommand(const std::string& command,
                         const std::vector<std::string>& args = {}) const;

    /**
     * @brief Authenticate current user
     * @return true if authenticated, false otherwise
     */
    bool authenticate() const;

    /**
     * @brief Get current user name
     * @return Current user name
     */
    std::string getCurrentUser() const;

    /**
     * @brief Load configuration from file
     * @param config_path Path to configuration file
     * @return true if successful, false otherwise
     */
    bool loadConfig(const std::string& config_path);

private:
    std::unique_ptr<Config> config_;
    std::unique_ptr<Security> security_;
    std::unique_ptr<Utils> utils_;
    std::unique_ptr<LuaConfig> lua_config_;
    std::string config_path_;
    bool non_interactive_;
    bool clear_timestamp_;

    // OpenDoas-style rule matching
    bool matchRule(const Rule& rule, uid_t uid, gid_t* groups, int ngroups,
                  uid_t target_uid, const std::string& command,
                  const std::vector<std::string>& args) const;

    // Enhanced permission checking
    bool permit(const std::string& command, const std::vector<std::string>& args,
               uid_t target_uid) const;
};

} // namespace Voix

#endif // VOIX_H
