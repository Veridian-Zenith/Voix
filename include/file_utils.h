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
#include <cstdint>

namespace Voix {

namespace fs = std::filesystem;

enum class FileError : std::uint8_t {
    NotFound,
    PermissionDenied,
    ReadError,
    WriteError,
    Unknown
};

class FileUtils {
public:
    /**
     * @brief Default constructor for FileUtils.
     */
    FileUtils() = default;
    /**
     * @brief Default destructor for FileUtils.
     */
    ~FileUtils() = default;

    /**
     * @brief Checks if a file exists at the given path.
     * @param path The path to the file.
     * @return True if the file exists, false otherwise.
     */
    bool fileExists(const fs::path& path) const;
    /**
     * @brief Checks if a path is secure (i.e., it does not contain dangerous components like '..').
     * @param path The path to check.
     * @return True if the path is secure, false otherwise.
     */
    bool isSecurePath(const fs::path& path) const;
    /**
     * @brief Reads the content of a file.
     * @param path The path to the file.
     * @return A std::expected containing the file content as a string on success, or a FileError on failure.
     */
    std::expected<std::string, FileError> readFile(const fs::path& path) const;
    /**
     * @brief Writes content to a file.
     * @param path The path to the file.
     * @param content The content to write.
     * @return A std::expected containing void on success, or a FileError on failure.
     */
    std::expected<void, FileError> writeFile(const fs::path& path, std::string_view content) const;
    /**
     * @brief Resolves a command to its full path based on the provided path environment.
     * @param command The command to resolve.
     * @param path_env The path environment string.
     * @return The resolved full path of the command, or the original command if not found.
     */
    std::string resolveCommand(const std::string& command, const std::string& path_env) const;
};

} // namespace Voix

#endif // FILE_UTILS_H
