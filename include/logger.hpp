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

/**
 * @brief Logger class for system logging.
 */
class Logger {
public:
    /**
     * @brief Flag to suppress printing to stderr (e.g., during tests).
     */
    static bool suppress_stderr;

    /**
     * @brief Default constructor for Logger.
     */
    Logger() = default;
    /**
     * @brief Default destructor for Logger.
     */
    ~Logger() = default;

    /**
     * @brief Gets the current system timestamp as a string.
     * @return The timestamp string.
     */
    std::string getTimestamp() const;
    /**
     * @brief Logs a message with a specified level.
     * @param level The log level (e.g., "INFO", "WARN", "ERROR").
     * @param message The message to log.
     */
    void log(std::string_view level, std::string_view message) const;
};

} // namespace Voix

#endif // LOGGER_H
