#include "file_utils.h"
#include <fstream>
#include <sstream>
#include <unistd.h>

namespace Voix {

bool FileUtils::fileExists(const Path& path) const {
  return access(path.c_str(), F_OK) == 0;
}

std::optional<std::string> FileUtils::readFile(const Path& path) const {
  std::ifstream file(path);
  if (!file.is_open()) {
    return std::nullopt;
  }

  std::stringstream buffer;
  buffer << file.rdbuf();
  file.close();

  return buffer.str();
}

bool FileUtils::writeFile(const Path& path, const Content& content) const {
  std::ofstream file(path);
  if (!file.is_open()) {
    return false;
  }

  file << content;
  file.close();

  return file.good();
}

} // namespace Voix
