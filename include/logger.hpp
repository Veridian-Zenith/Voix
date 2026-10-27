/**
 * @file logger.h
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef LOGGER_H
#define LOGGER_H

#include "exit_code.hpp"
#include <cstdint>
#include <string>
#include <string_view>

namespace Voix {

/// Fixed audit log location (intentionally not configurable).
constexpr const char* k_log_path = "/var/log/voix.log";

/**
 * @brief Severity of an audit-log record.
 *
 * Using an enum instead of a free-form string prevents a message from being
 * passed where a level is expected and keeps the syslog mapping exhaustive.
 */
enum class LogLevel : std::uint8_t { Info, Warning, Error, Security };

constexpr std::string_view log_level_name(LogLevel level) noexcept {
  switch (level) {
    case LogLevel::Info:
      return "INFO";
    case LogLevel::Warning:
      return "WARN";
    case LogLevel::Error:
      return "ERROR";
    case LogLevel::Security:
      return "SECURITY";
  }
  return "INFO";
}

#define LOG_ERROR(msg) Voix::Logger().log(Voix::LogLevel::Error, msg)
#define LOG_WARN(msg) Voix::Logger().log(Voix::LogLevel::Warning, msg)
#define LOG_INFO(msg) Voix::Logger().log(Voix::LogLevel::Info, msg)

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
     * @brief Logs a message with a specified level to /var/log/voix.log and
     *        syslog.
     * @param level The log level.
     * @param message The message to log.
     * @param echo_stderr Whether to also print a short line to stderr.
     */
    void log(LogLevel level, std::string_view message,
             bool echo_stderr = true) const;

    /**
     * @brief Reports a user-facing fatal error and records it in the audit log.
     *
     * The audit record carries the stable code; stderr carries a friendly
     * message plus an optional remediation hint. Unlike log(), this always
     * writes to stderr, because a fatal error must be visible even when
     * `core.suppress_stderr` is enabled.
     */
    void report_error(ExitCode code, std::string_view message,
                      std::string_view hint = {}) const;

    /**
     * @brief Reports a user-facing warning and records it in the audit log.
     * @param code Stable diagnostic code for log correlation.
     * @param message Human-readable warning.
     * @param hint Optional remediation hint.
     */
    void report_warning(std::string_view code, std::string_view message,
                        std::string_view hint = {}) const;
};

} // namespace Voix

#endif // LOGGER_H
