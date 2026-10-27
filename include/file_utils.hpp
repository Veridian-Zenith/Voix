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
#include <sys/types.h>

namespace Voix {

namespace fs = std::filesystem;

enum class FileError : std::uint8_t {
    NotFound,
    PermissionDenied,
    ReadError,
    WriteError,
    Unknown
};

constexpr std::string_view file_error_name(FileError error) noexcept {
    switch (error) {
        case FileError::NotFound: return "not-found";
        case FileError::PermissionDenied: return "permission-denied";
        case FileError::ReadError: return "read-error";
        case FileError::WriteError: return "write-error";
        case FileError::Unknown: return "unknown";
    }
    return "unknown";
}

/**
 * @brief Identity of a validated executable file.
 *
 * The device/inode pair pins the exact file that was validated. Callers must
 * pass this record to open_executable(); that method refuses to open a path
 * whose current inode differs, closing the validation-to-execution TOCTOU
 * window. Production code resolves against uid 0; tests may construct a
 * FileUtils with the current effective UID to exercise unprivileged files.
 */
struct ExecutableInfo {
    /// Fully resolved path (realpath) used for opening and execution.
    std::string path;
    /// Policy path: directory symlinks resolved, final component preserved.
    /// This keeps `/bin/ls` and `/usr/bin/ls` equivalent without collapsing
    /// distinct multicall names (`ls` and `cat`) into one executable.
    std::string policy_path;
    dev_t device = 0;
    ino_t inode = 0;
};

class FileUtils {
public:
    /**
     * @brief Constructs a FileUtils instance.
     * @param executable_owner UID that must own resolved executables. The
     *        production default is root (0); tests may use geteuid().
     */
    explicit FileUtils(uid_t executable_owner = 0)
        : executable_owner_(executable_owner) {}
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
     * @brief Resolves a command to a validated, canonical executable.
     *
     * Both absolute/relative paths containing '/' and bare names searched in
     * path_env are canonicalized with realpath(3). The resulting file must be
     * a regular executable owned by executable_owner (root by default), with
     * no group/world write bits. The returned device/inode pair is checked
     * again by open_executable().
     *
     * @param command Command path or bare name.
     * @param path_env Colon-separated PATH used for bare names.
     * @return Executable identity, or FileError on failure.
     */
    std::expected<ExecutableInfo, FileError>
    resolve_executable(std::string_view command, std::string_view path_env) const;
    /**
     * @brief Opens the exact executable validated by resolve_executable().
     *
     * Opens with O_NOFOLLOW|O_CLOEXEC and verifies on the descriptor that the
     * device/inode still match the validation result, that the file is a
     * regular executable owned by executable_owner, and that it is not
     * group/world writable. The returned descriptor is suitable for fexecve().
     *
     * @param info Result of resolve_executable().
     * @return Open read-only descriptor, or FileError on failure.
     */
    std::expected<int, FileError>
    open_executable(const ExecutableInfo& info) const;
    /**
     * @brief Resolves the absolute path of a command (legacy helper).
     * @param params Parameters containing the command and the PATH environment string to search.
     * @return The canonical absolute path, or an empty string if not found.
     */
    std::string resolve_command(const ResolveCommandParams& params) const;
    /**
     * @brief Checks whether a path is in a trusted, root-controlled location.
     *
     * The path must be absolute, and every component from '/' to the final
     * component must be root-owned and not group/world writable. Symlinked
     * components are rejected. This prevents `-C` from loading a root-owned
     * file through an attacker-controlled directory (e.g. /tmp), and is also
     * used to validate the sanctuary before tickets are read or written.
     *
     * @param path Path to validate.
     * @return True when the complete path is trusted.
     */
    bool is_trusted_path(const fs::path& path) const;

private:
    uid_t executable_owner_ = 0;
};

} // namespace Voix

#endif // FILE_UTILS_H
