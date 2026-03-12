#include "logger.h"
#include <chrono>
#include <format>
#include <fstream>
#include <string_view>

namespace Voix {

std::string Logger::getTimestamp() const {
  auto now = std::chrono::system_clock::now();
  return std::format("{:%Y-%m-%d %H:%M:%S}", now);
}

void Logger::log(std::string_view level, std::string_view message) const {
  std::ofstream log_file("/var/log/voix.log", std::ios::app);
  if (log_file.is_open()) {
    log_file << std::format("[{}] [{}] {}\n", getTimestamp(), level, message);
    log_file.close();
  }
}

} // namespace Voix
