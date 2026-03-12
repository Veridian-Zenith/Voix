#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <string_view>

namespace Voix {

class Logger {
public:
    Logger() = default;
    ~Logger() = default;

    std::string getTimestamp() const;
    void log(std::string_view level, std::string_view message) const;
};

} // namespace Voix

#endif // LOGGER_H
