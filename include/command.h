/**
 * @file command.h
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef COMMAND_H
#define COMMAND_H

#include "config.h"
#include <string>
#include <string_view>
#include <vector>

namespace Voix {

struct CommandOptions {
    bool preserve_env = false;
    bool login_shell = false;
    bool list_commands = false;
};

class Command {
public:
    Command() = default;
    ~Command() = default;

    int execute(std::string_view command,
                const std::vector<std::string>& args,
                const Config& config,
                const CommandOptions& options,
                std::string_view user = "root") const;

    std::string buildCommandString(std::string_view command,
                                   const std::vector<std::string>& args,
                                   std::string_view user) const;

private:
    void setResourceLimits() const;
};

} // namespace Voix

#endif // COMMAND_H
