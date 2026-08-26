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

namespace Voix {

/// Fixed audit log location (intentionally not configurable).
constexpr const char* k_log_path = "/var/log/voix.log";

#define LOG_ERROR(msg) Voix::Logger().log("ERROR", msg)
#define LOG_WARN(msg) Voix::Logger().log("WARN", msg)
#define LOG_INFO(msg) Voix::Logger().log("INFO", msg)

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
     * @brief Escapes control characters in a message so untrusted strings
     *        cannot forge additional log lines.
     * @param message The raw message.
     * @return The sanitized message.
     */
    static std::string sanitize_message(std::string_view message);
    /**
     * @brief Logs a message with a specified level to /var/log/voix.log,
     *        falling back to syslog if the file cannot be opened securely.
     * @param level The log level (e.g., "INFO", "WARN", "ERROR").
     * @param message The message to log.
     */
    void log(std::string_view level, std::string_view message) const;
};

} // namespace Voix

#endif // LOGGER_H
