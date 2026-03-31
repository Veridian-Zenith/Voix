/**
 * @file file_utils.h
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string>
#include <string_view>
#include <expected>
#include <filesystem>
#include <system_error>

namespace Voix {

namespace fs = std::filesystem;

enum class FileError {
    NotFound,
    PermissionDenied,
    ReadError,
    WriteError,
    Unknown
};

class FileUtils {
public:
    FileUtils() = default;
    ~FileUtils() = default;

    bool fileExists(const fs::path& path) const;
    bool isSecurePath(const fs::path& path) const;
    std::expected<std::string, FileError> readFile(const fs::path& path) const;
    std::expected<void, FileError> writeFile(const fs::path& path, std::string_view content) const;
};

} // namespace Voix

#endif // FILE_UTILS_H
