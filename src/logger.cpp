/**
 * @file logger.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "logger.hpp"
#include <chrono>
#include <cstddef>
#include <cstring>
#include <format>
#include <print>
#include <string_view>
#include <cstdio>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace Voix {

namespace {

/// Facility 10 (authpriv) and RFC 5424 severities are part of the syslog wire
/// format, so they are stable across libc implementations. Defining them here
/// avoids including <syslog.h>, whose LOG_* macros collide with this project's
/// LOG_* logging macros.
constexpr unsigned k_syslog_facility_authpriv = 10;

unsigned syslog_severity(LogLevel level) noexcept {
  switch (level) {
    case LogLevel::Info:
      return 6; // LOG_INFO
    case LogLevel::Warning:
      return 4; // LOG_WARNING
    case LogLevel::Error:
      return 3; // LOG_ERR
    case LogLevel::Security:
      return 5; // LOG_NOTICE
  }
  return 6;
}

/// Sends one record to the local syslog socket.
///
/// This is deliberately stateless. libc's syslog() caches its socket
/// descriptor across fork(); after a child scrubs its file descriptors that
/// cached number can refer to an unrelated descriptor (such as the pinned
/// executable at fd 3), which syslog() then closes. Opening, connecting,
/// sending, and closing per record keeps the logger independent of libc
/// private state and works the same under glibc and musl.
///
/// Failures are ignored: syslog is one of two sinks, and an unavailable
/// daemon must never affect the caller.
void send_to_syslog(LogLevel level, std::string_view message) {
  const int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return;
  }

  constexpr std::string_view k_log_socket = "/dev/log";
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  static_assert(sizeof(address.sun_path) > k_log_socket.size());
  std::memcpy(address.sun_path, k_log_socket.data(), k_log_socket.size());

  const auto address_length = static_cast<socklen_t>(
      offsetof(sockaddr_un, sun_path) + k_log_socket.size() + 1);
  if (::connect(fd, reinterpret_cast<sockaddr *>(&address), address_length) !=
      0) {
    ::close(fd);
    return;
  }

  const unsigned priority =
      (k_syslog_facility_authpriv << 3U) | syslog_severity(level);
  const std::string payload = std::format("<{}>{}", priority, message);
  (void)::send(fd, payload.data(), payload.size(), MSG_NOSIGNAL);
  ::close(fd);
}

} // namespace

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
  send_to_syslog(level, std::format("voix: [{}] [pid {}] {}", level_name,
                                    getpid(), safe_message));

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
