/**
 * @file file_utils.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "file_utils.hpp"
#include "logger.hpp"
#include <limits.h>
#include <fstream>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <format>
#include <sstream>
#include <fcntl.h>
#include <fcntl.h>

namespace Voix {

// Helper to open a file safely without following symlinks
static int open_no_follow(const char* path) {
    return open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
}

// Check if a file is safe (not a symlink, and proper permissions)
static bool is_file_safe(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return false;
    
    // Must be a regular file
    if (!S_ISREG(st.st_mode)) return false;
    
    // Must be owned by root
    if (st.st_uid != 0) return false;
    
    // Should not be world or group writable
    if (st.st_mode & (S_IWOTH | S_IWGRP)) return false;
    
    return true;
}

static bool check_path_safe(const fs::path& p) {
    char resolved_path[PATH_MAX];
    if (realpath(p.c_str(), resolved_path) == nullptr) {
        return false;
    }

    int fd = open_no_follow(resolved_path);
    if (fd == -1) return false;
    bool safe = is_file_safe(fd);
    close(fd);
    return safe;
}

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

std::expected<std::string, FileError> FileUtils::readFileSecure(const fs::path& path) const {
    int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        return std::unexpected(FileError::NotFound);
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return std::unexpected(FileError::ReadError);
    }

    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return std::unexpected(FileError::ReadError);
    }

    if (st.st_uid != 0) {
        close(fd);
        return std::unexpected(FileError::PermissionDenied);
    }

    if (st.st_mode & (S_IWOTH | S_IWGRP)) {
        close(fd);
        return std::unexpected(FileError::PermissionDenied);
    }

    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        close(fd);
        return std::unexpected(FileError::ReadError);
    }
    lseek(fd, 0, SEEK_SET);

    std::string content;
    content.resize(static_cast<size_t>(size));
    ssize_t bytes_read = read(fd, content.data(), size);
    close(fd);

    if (bytes_read != size) {
        return std::unexpected(FileError::ReadError);
    }

    return content;
}

std::string FileUtils::resolve_command(const ResolveCommandParams& params) const {
    const std::string& cmd = params.command;
    const std::string& paths = params.path_env;
    if (cmd.empty()) return "";

    // 1. If command contains '/', it's an explicit path.
    if (cmd.find('/') != std::string::npos) {
        fs::path p = fs::absolute(cmd);
        return check_path_safe(p) ? p.string() : "";
    }

    // 2. Otherwise, look up in $PATH.
    std::stringstream ss(paths);
    std::string item;
    while (std::getline(ss, item, ':')) {
        fs::path p = fs::path(item) / cmd;
        if (check_path_safe(p)) {
            return p.string();
        }
    }
    return "";
}

} // namespace Voix
