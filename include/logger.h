/**
 * @file logger.h
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <string_view>

#define LOG_ERROR(msg) Voix::Logger().log("ERROR", msg)
#define LOG_WARN(msg) Voix::Logger().log("WARN", msg)

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
