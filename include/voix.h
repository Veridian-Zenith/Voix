/**
 * @file voix.h
 * @brief Enhanced Voix header with OpenDoas integration
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef VOIX_H
#define VOIX_H

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <memory>
#include "command.h"

namespace Voix {

class Config;
class Security;
class IAuthenticator;
class PermissionChecker;

/**
 * @brief Main entry point for the Voix system.
 */
class Voix {
public:
    /**
     * @brief Constructor for Voix.
     * @param config_path Path to the configuration file.
     * @param non_interactive Whether to run in non-interactive mode.
     * @param clear_timestamp Whether to clear the timestamp.
     */
    Voix(std::string_view config_path = "/etc/voix.conf",
          bool non_interactive = false, bool clear_timestamp = false);
    /**
     * @brief Destructor for Voix.
     */
    ~Voix();

    /**
     * @brief Executes a command using the Voix system.
     * @param command The command to execute.
     * @param args The arguments for the command.
     * @param options The options for command execution.
     * @param user The user to execute the command as.
     * @return The return code of the command, or a non-zero value on failure.
     */
    int execute(std::string_view command,
                const std::vector<std::string>& args,
                const CommandOptions& options,
                std::string_view user = "root");

private:
    std::shared_ptr<Config> config_;
    std::shared_ptr<Security> security_;
    std::unique_ptr<IAuthenticator> authenticator_;
    std::unique_ptr<PermissionChecker> permission_checker_;
    std::unique_ptr<Command> command_;
    bool clear_timestamp_;
};

} // namespace Voix

#endif // VOIX_H
