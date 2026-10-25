/**
 * @file logger.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "logger.hpp"
#include <chrono>
#include <format>
#include <print>
#include <string_view>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>

namespace Voix {

bool Logger::suppress_stderr = false;

std::string Logger::getTimestamp() const {
  auto now = std::chrono::system_clock::now();
  return std::format("{:%Y-%m-%d %H:%M:%S}", now);
}

std::string Logger::sanitize_message(std::string_view message) {
  // Escape control characters so user-controlled strings (command paths,
  // usernames, arguments) cannot forge additional log lines.
  std::string out;
  out.reserve(message.size());
  for (char c : message) {
    auto uc = static_cast<unsigned char>(c);
    switch (c) {
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (uc < 0x20 || uc == 0x7f) {
          out += std::format("\\x{:02x}", uc);
        } else {
          out += c;
        }
    }
  }
  return out;
}

void Logger::log(LogLevel level, std::string_view message,
                 bool echo_stderr) const {
  const std::string safe_message = sanitize_message(message);
  const std::string_view level_name = log_level_name(level);
  const std::string line = std::format("[{}] [{}] [pid {}] {}\n",
                                       getTimestamp(), level_name, getpid(),
                                       safe_message);

  int fd = open(k_log_path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                0640);
  if (fd >= 0) {
    size_t total = 0;
    while (total < line.size()) {
      ssize_t n = write(fd, line.data() + total, line.size() - total);
      if (n < 0) {
        if (errno == EINTR) continue;
        break;
      }
      total += static_cast<size_t>(n);
    }
    close(fd);
  }

  // Syslog is always a sink, not just a fallback: audit records must survive
  // a missing or unwritable log file, and remote logging is often configured
  // through syslog. The file above is the durable local copy.
  int priority = LOG_AUTHPRIV | LOG_INFO;
  switch (level) {
    case LogLevel::Info:
      priority = LOG_AUTHPRIV | LOG_INFO;
      break;
    case LogLevel::Warning:
      priority = LOG_AUTHPRIV | LOG_WARNING;
      break;
    case LogLevel::Error:
      priority = LOG_AUTHPRIV | LOG_ERR;
      break;
    case LogLevel::Security:
      priority = LOG_AUTHPRIV | LOG_NOTICE;
      break;
  }
  syslog(priority, "voix: [%.*s] [pid %d] %.*s",
         static_cast<int>(level_name.size()), level_name.data(), getpid(),
         static_cast<int>(safe_message.size()), safe_message.data());

  if (echo_stderr && !suppress_stderr) {
    std::println(stderr, "voix: [{}] {}", level_name, safe_message);
  }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void Logger::report_error(ExitCode code, std::string_view message,
                          std::string_view hint) const {
  log(LogLevel::Error, std::format("[{}] {}", exit_code_name(code), message),
      false);

  // Fatal errors bypass core.suppress_stderr: silently failing would make
  // permission and configuration problems impossible to diagnose.
  std::println(stderr, "voix: error: {}", sanitize_message(message));
  if (!hint.empty()) {
    std::println(stderr, "voix: hint: {}", sanitize_message(hint));
  }
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void Logger::report_warning(std::string_view code, std::string_view message,
                            std::string_view hint) const {
  log(LogLevel::Warning, std::format("[{}] {}", code, message), false);
  if (!suppress_stderr) {
    std::println(stderr, "voix: warning: {}", sanitize_message(message));
    if (!hint.empty()) {
      std::println(stderr, "voix: hint: {}", sanitize_message(hint));
    }
  }
}

} // namespace Voix
