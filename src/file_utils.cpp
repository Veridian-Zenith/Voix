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
#include <optional>
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
    if (st.st_mode & static_cast<mode_t>(S_IWOTH | S_IWGRP)) return false;

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
    if (st.st_mode & ~static_cast<mode_t>(S_IFMT | S_IRWXU)) return false;

    return true;
}

std::expected<ExecutableInfo, FileError>
// The parameter names make the call sites self-documenting
// (`resolve_executable(name, config.getPath())`); a strong type for the
// search path would add ceremony without preventing a real mistake.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
FileUtils::resolve_executable(std::string_view command,
                              std::string_view path_env) const {
    if (command.empty()) {
        return std::unexpected(FileError::NotFound);
    }

    // Validate one candidate and return its canonical path plus the inode
    // identity. realpath(3) collapses symlinks and relative components; the
    // ownership/mode checks are performed on that canonical path.
    auto check_candidate = [this](const fs::path& candidate)
        -> std::expected<ExecutableInfo, FileError> {
        char resolved_path[PATH_MAX];
        if (realpath(candidate.c_str(), resolved_path) == nullptr) {
            return std::unexpected(errno_to_file_error(errno, FileError::NotFound));
        }

        struct stat st;
        if (::stat(resolved_path, &st) != 0) {
            return std::unexpected(errno_to_file_error(errno, FileError::ReadError));
        }

        if (!S_ISREG(st.st_mode)) {
            return std::unexpected(FileError::PermissionDenied);
        }
        if (st.st_uid != executable_owner_) {
            return std::unexpected(FileError::PermissionDenied);
        }
        if (st.st_mode & static_cast<mode_t>(S_IWOTH | S_IWGRP)) {
            return std::unexpected(FileError::PermissionDenied);
        }
        if ((st.st_mode & static_cast<mode_t>(S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
            return std::unexpected(FileError::PermissionDenied);
        }

        // Preserve the final component while canonicalizing its directory.
        // Resolving the final symlink would make every multicall applet
        // (/usr/bin/ls, /usr/bin/cat, ...) share one policy identity.
        std::error_code ec;
        fs::path absolute = fs::absolute(candidate, ec);
        std::string policy_path =
            ec ? std::string(resolved_path) : absolute.lexically_normal().string();
        if (!ec && !absolute.filename().empty()) {
            char resolved_parent[PATH_MAX];
            if (realpath(absolute.parent_path().c_str(), resolved_parent) != nullptr) {
                policy_path =
                    (fs::path(resolved_parent) / absolute.filename()).string();
            }
        }

        return ExecutableInfo{resolved_path, policy_path, st.st_dev, st.st_ino};
    };

    // 1. A path containing '/' is explicit (absolute or relative).
    if (command.find('/') != std::string_view::npos) {
        std::error_code ec;
        fs::path absolute = fs::absolute(fs::path(command), ec);
        if (ec) {
            return std::unexpected(FileError::NotFound);
        }
        return check_candidate(absolute);
    }

    // 2. Otherwise search the configured PATH in order. Remember the first
    // non-NotFound failure so an unsafe-but-present candidate produces
    // "permission denied" rather than a misleading "not found".
    std::optional<FileError> first_error;
    std::stringstream ss{std::string(path_env)};
    std::string item;
    while (std::getline(ss, item, ':')) {
        if (item.empty()) continue;
        auto result = check_candidate(fs::path(item) / std::string(command));
        if (result) {
            return result;
        }
        if (result.error() != FileError::NotFound && !first_error) {
            first_error = result.error();
        }
    }
    return std::unexpected(first_error.value_or(FileError::NotFound));
}

std::expected<int, FileError>
FileUtils::open_executable(const ExecutableInfo& info) const {
    int fd = open_no_follow(info.path.c_str());
    if (fd == -1) {
        return std::unexpected(errno_to_file_error(errno, FileError::ReadError));
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return std::unexpected(FileError::ReadError);
    }

    // The path may have been replaced after resolve_executable(). Refuse any
    // inode other than the one that was validated.
    if (st.st_dev != info.device || st.st_ino != info.inode) {
        close(fd);
        return std::unexpected(FileError::PermissionDenied);
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != executable_owner_ ||
        (st.st_mode & static_cast<mode_t>(S_IWOTH | S_IWGRP)) != 0 ||
        (st.st_mode & static_cast<mode_t>(S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        close(fd);
        return std::unexpected(FileError::PermissionDenied);
    }

    return fd;
}

std::string FileUtils::resolve_command(const ResolveCommandParams& params) const {
    auto result = resolve_executable(params.command, params.path_env);
    return result ? result->path : "";
}

bool FileUtils::is_trusted_config_path(const fs::path& path) const {
    if (path.empty() || !path.is_absolute()) {
        return false;
    }

    // Walk the original (lexically normalized) path rather than realpath() so
    // a symlinked component is rejected instead of silently followed.
    fs::path normalized = path.lexically_normal();
    fs::path current;
    for (const auto& component : normalized) {
        if (component == "/") {
            current = "/";
            continue;
        }
        if (component == ".") {
            continue;
        }
        if (component == "..") {
            return false;
        }
        current /= component;

        struct stat st;
        if (::lstat(current.c_str(), &st) != 0) {
            return false;
        }
        if (S_ISLNK(st.st_mode)) {
            return false;
        }
        if (st.st_uid != 0) {
            return false;
        }
        if (st.st_mode & static_cast<mode_t>(S_IWOTH | S_IWGRP)) {
            return false;
        }
        if (current != normalized && !S_ISDIR(st.st_mode)) {
            return false;
        }
    }

    return true;
}

} // namespace Voix
