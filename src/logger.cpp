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

void Logger::log(std::string_view level, std::string_view message) const {
  const std::string line = std::format("[{}] [{}] {}\n",
                                       getTimestamp(), level,
                                       sanitize_message(message));

  int fd = open(k_log_path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0640);
  if (fd >= 0) {
    size_t total = 0;
    bool ok = true;
    while (total < line.size()) {
      ssize_t n = write(fd, line.data() + total, line.size() - total);
      if (n < 0) {
        if (errno == EINTR) continue;
        ok = false;
        break;
      }
      total += static_cast<size_t>(n);
    }
    close(fd);
    if (ok) {
      if (!suppress_stderr) {
        std::println(stderr, "voix: [{}] {}", level, sanitize_message(message));
      }
      return;
    }
  }

  // File unavailable (not root, missing dir, foreign symlink): syslog fallback.
  int priority = LOG_AUTHPRIV | LOG_INFO;
  if (level == "ERROR") priority = LOG_AUTHPRIV | LOG_ERR;
  else if (level == "WARN") priority = LOG_AUTHPRIV | LOG_WARNING;
  syslog(priority, "voix: [%.*s] %.*s",
         static_cast<int>(level.size()), level.data(),
         static_cast<int>(sanitize_message(message).size()),
         sanitize_message(message).data());
  if (!suppress_stderr) {
    std::println(stderr, "voix: [{}] {}", level, sanitize_message(message));
  }
}

} // namespace Voix
