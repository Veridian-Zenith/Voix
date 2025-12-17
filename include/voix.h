/**
 * @file voix.h
 * @brief Main Voix header file
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
class PAMAuth;

/**
 * @brief Main Voix class that handles privilege escalation
 */
class Voix {
public:
    Voix(const std::string& config_path = "/etc/voix.conf");
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
                const std::optional<std::string>& user = std::nullopt);

    /**
     * @brief Check if current user can use Voix
     * @return true if allowed, false otherwise
     */
    bool isAllowed() const;

    /**
     * @brief Validate command before execution
     * @param command Command to validate
     * @return true if valid, false otherwise
     */
    bool validateCommand(const std::string& command) const;

    /**
     * @brief Authenticate current user using PAM
     * @return true if authenticated, false otherwise
     */
    bool authenticate() const;

private:
    std::unique_ptr<Config> config_;
    std::unique_ptr<Security> security_;
    std::unique_ptr<Utils> utils_;
    std::unique_ptr<PAMAuth> pam_auth_;
    std::string config_path_;
};

} // namespace Voix

#endif // VOIX_H
