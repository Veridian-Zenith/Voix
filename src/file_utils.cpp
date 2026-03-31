/**
 * @file file_utils.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "file_utils.h"
#include "logger.h"
#include <fstream>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <format>

namespace Voix {

bool FileUtils::fileExists(const fs::path& path) const {
  std::error_code ec;
  return fs::exists(path, ec);
}

bool FileUtils::isSecurePath(const fs::path& path) const {
  struct stat st;
  Logger logger;
  if (stat(path.c_str(), &st) != 0) {
    logger.log("ERROR", std::format("Failed to stat path: {}", path.string()));
    return false;
  }

  // 1. File must be owned by root (UID 0)
  if (st.st_uid != 0) {
    logger.log("ERROR", std::format("Path is not owned by root: {}", path.string()));
    return false;
  }

  // 2. File must not be world-writable
  if (st.st_mode & S_IWOTH) {
    logger.log("ERROR", std::format("Path is world-writable: {}", path.string()));
    return false;
  }

  // File should not be group-writable either, but only "not world-writable" was mandatory.
  // "ideally only writable by root" implies we should also check group-writable.
  if (st.st_mode & S_IWGRP) {
    logger.log("ERROR", std::format("Path is group-writable (ideally root only): {}", path.string()));
    return false;
  }

  // 3. The directory containing the file is also secure (owned by root and not world-writable).
  fs::path parent = path.parent_path();
  if (parent.empty()) {
    parent = ".";
  }

  struct stat pst;
  if (stat(parent.c_str(), &pst) != 0) {
    logger.log("ERROR", std::format("Failed to stat parent directory: {}", parent.string()));
    return false;
  }

  if (pst.st_uid != 0) {
    logger.log("ERROR", std::format("Parent directory is not owned by root: {}", parent.string()));
    return false;
  }

  if (pst.st_mode & S_IWOTH) {
    logger.log("ERROR", std::format("Parent directory is world-writable: {}", parent.string()));
    return false;
  }

  if (pst.st_mode & S_IWGRP) {
    logger.log("ERROR", std::format("Parent directory is group-writable (ideally root only): {}", parent.string()));
    return false;
  }

  return true;
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
