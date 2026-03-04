#ifndef COMMAND_H
#define COMMAND_H

#include <string>
#include <vector>

namespace Voix {

class Command {
public:
    Command() = default;
    ~Command() = default;

    int execute(const std::string& command,
                const std::vector<std::string>& args,
                const std::string& user = "root") const;

    std::string buildCommandString(const std::string& command,
                                   const std::vector<std::string>& args,
                                   const std::string& user) const;
};

} // namespace Voix

#endif // COMMAND_H
