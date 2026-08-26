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
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <format>
#include <sstream>

namespace Voix {

// Helper to open a file safely without following symlinks
static int open_no_follow(const char* path) {
    return open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
}

// Check if an open file descriptor refers to a regular file owned by the
// current effective UID with no group/world write permission.
static bool is_file_safe(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return false;

    // Must be a regular file
    if (!S_ISREG(st.st_mode)) return false;

    // Must be owned by the effective user (root for setuid voix)
    if (st.st_uid != geteuid()) return false;

    // Must not be group or world writable
    if (st.st_mode & (S_IWOTH | S_IWGRP)) return false;

    return true;
}

static FileError errno_to_file_error(int err, FileError fallback) {
    switch (err) {
        case ENOENT: case ENOTDIR: return FileError::NotFound;
        case EACCES: case EPERM: case ELOOP: return FileError::PermissionDenied;
        default: return fallback;
    }
}

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

std::expected<std::string, FileError> FileUtils::read_file_secure(const fs::path& path) const {
    int fd = open_no_follow(path.c_str());
    if (fd == -1) {
        return std::unexpected(errno_to_file_error(errno, FileError::ReadError));
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !is_file_safe(fd)) {
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

    // Loop until fully read; single read() calls may return short.
    size_t total = 0;
    while (total < content.size()) {
        ssize_t n = read(fd, content.data() + total, content.size() - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return std::unexpected(FileError::ReadError);
        }
        if (n == 0) break;  // File shrank between fstat and read
        total += static_cast<size_t>(n);
    }
    close(fd);

    content.resize(total);
    if (total != static_cast<size_t>(size)) {
        return std::unexpected(FileError::ReadError);
    }

    return content;
}

std::expected<void, FileError> FileUtils::write_file_secure(const fs::path& path,
                                                            std::string_view content) const {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd == -1) {
        return std::unexpected(errno_to_file_error(errno, FileError::WriteError));
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !is_file_safe(fd)) {
        close(fd);
        return std::unexpected(FileError::PermissionDenied);
    }

    size_t total = 0;
    while (total < content.size()) {
        ssize_t n = write(fd, content.data() + total, content.size() - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return std::unexpected(FileError::WriteError);
        }
        total += static_cast<size_t>(n);
    }
    close(fd);
    return {};
}

bool FileUtils::ensure_private_directory(const fs::path& path) const {
    std::error_code ec;
    fs::create_directory(path, ec);  // OK if it already exists
    (void)ec;

    // Force strict permissions regardless of prior state.
    if (::chmod(path.c_str(), S_IRWXU) != 0) {
        return false;
    }

    struct stat st;
    if (::stat(path.c_str(), &st) != 0) {
        return false;
    }

    // Must be a directory owned by the effective UID with mode exactly 0700.
    if (!S_ISDIR(st.st_mode)) return false;
    if (st.st_uid != geteuid()) return false;
    if (st.st_mode & ~(S_IFMT | S_IRWXU)) return false;

    return true;
}

std::string FileUtils::resolve_command(const ResolveCommandParams& params) const {
    const std::string& cmd = params.command;
    const std::string& paths = params.path_env;
    if (cmd.empty()) return "";

    // Helper: verify a candidate path is a safe root-owned executable.
    // Runs in the forked child AFTER the privilege drop, so ownership is
    // checked against root (uid 0) explicitly — never against the current
    // effective user.
    auto check_path_safe = [](const fs::path& p) -> bool {
        char resolved_path[PATH_MAX];
        if (realpath(p.c_str(), resolved_path) == nullptr) {
            return false;
        }

        int fd = open_no_follow(resolved_path);
        if (fd == -1) return false;
        struct stat st;
        bool safe = false;
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
            st.st_uid == 0 &&
            !(st.st_mode & (S_IWOTH | S_IWGRP))) {
            safe = true;
        }
        close(fd);
        return safe;
    };

    // 1. If command contains '/', it's an explicit path.
    if (cmd.find('/') != std::string::npos) {
        fs::path p = fs::absolute(cmd);
        return check_path_safe(p) ? p.string() : "";
    }

    // 2. Otherwise, look up in $PATH.
    std::stringstream ss(paths);
    std::string item;
    while (std::getline(ss, item, ':')) {
        if (item.empty()) continue;
        fs::path p = fs::path(item) / cmd;
        if (check_path_safe(p)) {
            return p.string();
        }
    }
    return "";
}

} // namespace Voix
