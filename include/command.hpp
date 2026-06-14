/**
 * @file command.h
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef COMMAND_H
#define COMMAND_H

#include "config.hpp"
#include <string>
#include <string_view>
#include <vector>

namespace Voix {

/**
 * @brief Options for command execution.
 */
struct CommandOptions {
    bool preserve_env = false; /**< Whether to preserve the environment variables. */
    bool login_shell = false;  /**< Whether to execute the command as a login shell. */
    bool list_commands = false; /**< Whether to list available commands. */
    bool check_config = false; /**< Whether to check configuration. */
};

/**
 * @brief Handles the execution of commands with given options and configuration.
 */
class Command {
public:
    /**
     * @brief Default constructor for Command.
     */
    Command() = default;
    /**
     * @brief Default destructor for Command.
     */
    ~Command() = default;

    /**
     * @brief Executes a command with given arguments and options.
     * @param command The command to execute.
     * @param args The arguments for the command.
     * @param config The configuration to use.
     * @param options The options for command execution.
     * @param user The user to execute the command as.
     * @return The return code of the command, or a non-zero value on failure.
     */
    int execute(std::string_view command,
                const std::vector<std::string>& args,
                const Config& config,
                const CommandOptions& options,
                std::string_view user = "root") const;

    /**
     * @brief Builds a command string for logging or debugging.
     * @param command The command.
     * @param args The arguments.
     * @param user The user.
     * @return The built command string.
     */
    std::string buildCommandString(std::string_view command,
                                    const std::vector<std::string>& args,
                                    std::string_view user) const;

private:
    /**
     * @brief Sets resource limits for the executed command.
     */
    void setResourceLimits() const;
};

} // namespace Voix

#endif // COMMAND_H
