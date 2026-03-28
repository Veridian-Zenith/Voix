/**
 * @file file_utils.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "file_utils.h"
#include <fstream>
#include <sstream>
#include <unistd.h>

namespace Voix {

bool FileUtils::fileExists(Path path) const {
  std::string path_str{path};
  return access(path_str.c_str(), F_OK) == 0;
}

std::optional<std::string> FileUtils::readFile(Path path) const {
  std::string path_str{path};
  std::ifstream file(path_str);
  if (!file.is_open()) {
    return std::nullopt;
  }

  std::stringstream buffer;
  buffer << file.rdbuf();
  file.close();

  return buffer.str();
}

bool FileUtils::writeFile(Path path, Content content) const {
  std::string path_str{path};
  std::ofstream file(path_str);
  if (!file.is_open()) {
    return false;
  }

  file << content;
  file.close();

  return file.good();
}

} // namespace Voix
