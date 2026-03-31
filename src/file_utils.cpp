/**
 * @file file_utils.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "file_utils.h"
#include <fstream>
#include <system_error>

namespace Voix {

bool FileUtils::fileExists(const fs::path& path) const {
  std::error_code ec;
  return fs::exists(path, ec);
}

std::expected<std::string, FileError> FileUtils::readFile(const fs::path& path) const {
  std::error_code ec;
  if (!fs::exists(path, ec)) {
    return std::unexpected(FileError::NotFound);
  }

  uintmax_t size = fs::file_size(path, ec);
  if (ec) {
    return std::unexpected(FileError::ReadError);
  }

  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    return std::unexpected(FileError::PermissionDenied);
  }

  std::string content;
  content.resize_and_overwrite(size, [&](char* buf, size_t n) {
    file.read(buf, static_cast<std::streamsize>(n));
    return static_cast<size_t>(file.gcount());
  });

  if (file.bad()) {
    return std::unexpected(FileError::ReadError);
  }

  return content;
}

std::expected<void, FileError> FileUtils::writeFile(const fs::path& path, std::string_view content) const {
  std::ofstream file(path, std::ios::binary);
  if (!file.is_open()) {
    return std::unexpected(FileError::PermissionDenied);
  }

  file << content;
  if (file.bad()) {
    return std::unexpected(FileError::WriteError);
  }

  return {};
}

} // namespace Voix
