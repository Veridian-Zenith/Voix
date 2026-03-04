#ifndef LOGGER_H
#define LOGGER_H

#include <string>

namespace Voix {

class Logger {
public:
    Logger() = default;
    ~Logger() = default;

    std::string getTimestamp() const;
    void log(const std::string& level, const std::string& message) const;
};

} // namespace Voix

#endif // LOGGER_H
