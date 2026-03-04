#include "logger.h"
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace Voix {

std::string Logger::getTimestamp() const {
  auto now = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;

  std::stringstream ss;
  ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "."
     << std::setfill('0') << std::setw(3) << ms.count();

  return ss.str();
}

void Logger::log(const std::string& level, const std::string& message) const {
  std::string timestamp = getTimestamp();
  std::string log_entry = "[" + timestamp + "] [" + level + "] " + message;

  std::ofstream log_file("/var/log/voix.log", std::ios::app);
  if (log_file.is_open()) {
    log_file << log_entry << '\n';
    log_file.close();
  }
}

} // namespace Voix
