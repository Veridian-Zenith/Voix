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
     * @brief Reads the content of a file.
     * @param path The path to the file.
     * @return A std::expected containing the file content as a string on success, or a FileError on failure.
     */
    std::expected<std::string, FileError> readFile(const fs::path& path) const;
    /**
     * @brief Reads a file securely using O_NOFOLLOW to prevent TOCTOU.
     *
     * Opens the file, verifies it is a regular file owned by the current
     * effective UID (root in the setuid production context) with no
     * group/world write bits, then reads the content. All checks are done on
     * the open file descriptor.
     *
     * @param path The path to the file.
     * @return File content on success, or FileError on failure.
     */
    std::expected<std::string, FileError> read_file_secure(const fs::path& path) const;
    /**
     * @brief Writes content to a file securely using O_NOFOLLOW.
     *
     * Creates/truncates the file with mode 0600, refuses symlinks (O_NOFOLLOW),
     * verifies on the opened descriptor that it is a regular file owned by the
     * current effective UID with no group/world write bits, and loops until the
     * entire buffer is written. Intended for root-owned runtime state such as
     * authentication timestamps.
     *
     * @param path The path to the file.
     * @param content The content to write.
     * @return Success, or FileError on failure.
     */
    std::expected<void, FileError> write_file_secure(const fs::path& path, std::string_view content) const;
    /**
     * @brief Ensures a directory exists with strict private permissions.
     *
     * Creates the directory if missing, forces mode 0700 via chmod, and then
     * verifies on the resulting path that it is a directory owned by the
     * current effective UID with no group/world permission bits. Returns false
     * if any invariant cannot be established (e.g. an attacker-created
     * directory with a foreign owner).
     *
     * @param path The directory path.
     * @return True if the directory is private and safe to use.
     */
    bool ensure_private_directory(const fs::path& path) const;
    struct ResolveCommandParams {
        std::string command;
        std::string path_env;
    };
    /**
     * @brief Resolves the absolute path of a command.
     * @param params Parameters containing the command and the PATH environment string to search.
     * @return The absolute path to the command, or an empty string if not found.
     */
    std::string resolve_command(const ResolveCommandParams& params) const;

};

} // namespace Voix

#endif // FILE_UTILS_H
