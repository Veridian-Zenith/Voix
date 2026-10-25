/**
 * @file test_file_utils.cpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

/**
 * @file test_file_utils.cpp
 * @brief FileUtils unit tests, including secure read/write primitives.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

#include "test_modules.hpp"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>

bool test_file_exists() {
    Voix::FileUtils file_utils;

    std::filesystem::path test_dir = std::filesystem::temp_directory_path() / "voix_test_file_exists";
    std::filesystem::path existing_file = test_dir / "existing.txt";
    std::filesystem::path missing_file = test_dir / "missing.txt";

    std::filesystem::create_directories(test_dir);
    {
        std::ofstream out(existing_file);
        out << "test";
    }

    ASSERT_TRUE(file_utils.fileExists(existing_file.string()));
    ASSERT_TRUE(!file_utils.fileExists(missing_file.string()));

    std::filesystem::remove_all(test_dir);
    return true;
}

bool test_read_file_success() {
    Voix::FileUtils file_utils;
    std::filesystem::path test_dir = std::filesystem::temp_directory_path() / "voix_test_read";
    std::filesystem::path test_file = test_dir / "readable.txt";
    ScopedTempFile dir_guard(test_dir, true);

    std::filesystem::create_directories(test_dir);
    {
        std::ofstream out(test_file);
        out << "hello world";
    }

    auto result = file_utils.readFile(test_file);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQUAL(result.value(), std::string("hello world"));

    return true;
}

bool test_read_file_not_found() {
    Voix::FileUtils file_utils;
    auto result = file_utils.readFile("/tmp/voix_nonexistent_file_xyz.txt");
    ASSERT_TRUE(!result.has_value());
    ASSERT_EQUAL(static_cast<int>(result.error()), static_cast<int>(Voix::FileError::NotFound));
    return true;
}

bool test_read_file_empty() {
    Voix::FileUtils file_utils;
    std::filesystem::path test_dir = std::filesystem::temp_directory_path() / "voix_test_read_empty";
    std::filesystem::path test_file = test_dir / "empty.txt";
    ScopedTempFile dir_guard(test_dir, true);

    std::filesystem::create_directories(test_dir);
    {
        std::ofstream out(test_file);
    }

    auto result = file_utils.readFile(test_file);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQUAL(result.value(), std::string(""));

    return true;
}

bool test_resolve_command_empty() {
    Voix::FileUtils file_utils;
    std::string result = file_utils.resolve_command({"", "/usr/bin:/bin"});
    ASSERT_EQUAL(result, std::string(""));
    return true;
}

bool test_resolve_command_absolute_nonexistent() {
    Voix::FileUtils file_utils;
    std::string result = file_utils.resolve_command({"/nonexistent/binary", "/usr/bin"});
    ASSERT_EQUAL(result, std::string(""));
    return true;
}

bool test_resolve_command_not_in_path() {
    Voix::FileUtils file_utils;
    std::string result = file_utils.resolve_command({"totally_fake_command_xyz123", "/usr/bin:/bin"});
    ASSERT_EQUAL(result, std::string(""));
    return true;
}

bool test_resolve_command_rejects_group_writable() {
    ScopedTempFile dir("/tmp/voix_test_rescmd", true);
    auto root = std::filesystem::temp_directory_path() / "voix_test_rescmd";
    std::filesystem::create_directories(root / "bin");
    auto exe = root / "bin" / "tool";
    {
        std::ofstream out(exe);
        out << "#!/bin/sh\nexit 0\n";
    }
    std::filesystem::permissions(exe, std::filesystem::perms::owner_all |
                                       std::filesystem::perms::group_read |
                                       std::filesystem::perms::group_exec,
                                 std::filesystem::perm_options::replace);

    Voix::FileUtils fu;
    // Group-writable candidate is refused even though it exists.
    std::filesystem::permissions(exe, std::filesystem::perms::owner_all |
                                       std::filesystem::perms::group_read |
                                       std::filesystem::perms::group_write |
                                       std::filesystem::perms::group_exec,
                                 std::filesystem::perm_options::replace);
    ASSERT_EQUAL(fu.resolve_command({(root / "tool").string(), ""}), std::string(""));

    // Absolute form with group-write bits must also be rejected.
    ASSERT_EQUAL(fu.resolve_command({exe.string(), ""}), std::string(""));
    return true;
}

bool test_secure_read_write_roundtrip() {
    ScopedTempFile dir("/tmp/voix_test_secio", true);
    auto dir_path = std::filesystem::temp_directory_path() / "voix_test_secio";
    std::filesystem::create_directories(dir_path);

    Voix::FileUtils fu;
    auto f = dir_path / "ticket";

    ASSERT_TRUE(!fu.read_file_secure(f).has_value());  // Missing

    auto w = fu.write_file_secure(f, "1727000000");
    ASSERT_TRUE(w.has_value());

    // Mode must be 0600 and owned by the effective user.
    struct stat st;
    ASSERT_TRUE(stat(f.c_str(), &st) == 0);
    ASSERT_EQUAL(st.st_mode & 0777, 0600u);
    ASSERT_EQUAL(st.st_uid, static_cast<uid_t>(geteuid()));

    auto r = fu.read_file_secure(f);
    ASSERT_TRUE(r.has_value());
    ASSERT_EQUAL(r.value(), std::string("1727000000"));

    // Overwrite works.
    ASSERT_TRUE(fu.write_file_secure(f, "updated").has_value());
    auto r2 = fu.read_file_secure(f);
    ASSERT_TRUE(r2.has_value());
    ASSERT_EQUAL(r2.value(), std::string("updated"));
    return true;
}

bool test_secure_io_rejects_symlink() {
    ScopedTempFile dir("/tmp/voix_test_seclink", true);
    auto dir_path = std::filesystem::temp_directory_path() / "voix_test_seclink";
    std::filesystem::create_directories(dir_path);

    Voix::FileUtils fu;
    auto target = dir_path / "victim";
    {
        std::ofstream out(target);
        out << "original";
    }
    auto link = dir_path / "link";
    std::error_code ec;
    std::filesystem::create_symlink(target, link, ec);
    ASSERT_TRUE(!ec);

    // O_NOFOLLOW: both operations refuse the symlink instead of following it.
    ASSERT_TRUE(!fu.write_file_secure(link, "pwned").has_value());
    ASSERT_TRUE(!fu.read_file_secure(link).has_value());

    // Victim content untouched.
    auto r = fu.readFile(target);
    ASSERT_TRUE(r.has_value());
    ASSERT_EQUAL(r.value(), std::string("original"));
    return true;
}

bool test_private_directory_enforced() {
    ScopedTempFile guard("/tmp/voix_test_privdir", true);
    auto base = std::filesystem::temp_directory_path() / "voix_test_privdir";
    std::filesystem::create_directories(base);

    Voix::FileUtils fu;
    auto sub = base / "timestamp";
    ASSERT_TRUE(fu.ensure_private_directory(sub));

    struct stat st;
    ASSERT_TRUE(stat(sub.c_str(), &st) == 0);
    ASSERT_EQUAL(st.st_mode & 0777, 0700u);

    // A loose pre-existing directory gets tightened but then fails ownership
    // only if foreign — here it is ours, so tightening succeeds.
    auto loose = base / "loose";
    std::filesystem::create_directory(loose);
    std::filesystem::permissions(loose, std::filesystem::perms::all, std::filesystem::perm_options::replace);
    ASSERT_TRUE(fu.ensure_private_directory(loose));
    ASSERT_TRUE(stat(loose.c_str(), &st) == 0);
    ASSERT_EQUAL(st.st_mode & 0777, 0700u);
    return true;
}

bool test_resolve_executable_rejects_user_owned_by_default() {
    ScopedTempFile guard("/tmp/voix_test_exec_owner", true);
    auto dir = std::filesystem::temp_directory_path() / "voix_test_exec_owner";
    std::filesystem::create_directories(dir);
    auto exe = dir / "tool";
    {
        std::ofstream out(exe);
        out << "#!/bin/sh\nexit 0\n";
    }
    std::filesystem::permissions(exe, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);

    Voix::FileUtils production;
    ASSERT_TRUE(!production.resolve_executable(exe.string(), ""));

    Voix::FileUtils test_owned(geteuid());
    auto resolved = test_owned.resolve_executable(exe.string(), "");
    ASSERT_TRUE(resolved.has_value());
    ASSERT_EQUAL(resolved->path, std::filesystem::canonical(exe).string());
    return true;
}

bool test_resolve_executable_canonicalizes_symlink() {
    Voix::FileUtils fu;
    auto resolved = fu.resolve_executable("/bin/true", "");
    ASSERT_TRUE(resolved.has_value());
    ASSERT_EQUAL(resolved->path, std::filesystem::canonical("/bin/true").string());
    return true;
}

bool test_executable_replacement_is_pinned() {
    ScopedTempFile guard("/tmp/voix_test_exec_replace", true);
    auto dir = std::filesystem::temp_directory_path() / "voix_test_exec_replace";
    std::filesystem::create_directories(dir);
    auto exe = dir / "tool";
    auto replacement = dir / "replacement";

    // Start from a real ELF executable so fexecve() does not depend on the
    // kernel's script-interpreter re-open path.
    std::filesystem::copy_file("/bin/sh", exe,
                               std::filesystem::copy_options::overwrite_existing);
    std::filesystem::permissions(exe, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);

    Voix::FileUtils fu(geteuid());
    auto info = fu.resolve_executable(exe.string(), "");
    ASSERT_TRUE(info.has_value());
    auto opened = fu.open_executable(*info);
    ASSERT_TRUE(opened.has_value());
    const int fd = *opened;

    // Replace the path after validation. The old inode stays pinned by fd.
    {
        std::ofstream out(replacement);
        out << "#!/bin/sh\necho replaced\n";
    }
    std::filesystem::permissions(replacement, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);
    std::filesystem::rename(replacement, exe);

    // Re-opening the validated path must refuse the new inode.
    auto reopened = fu.open_executable(*info);
    ASSERT_TRUE(!reopened.has_value());

    int pipefd[2];
    ASSERT_TRUE(pipe(pipefd) == 0);
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        const int flags = fcntl(fd, F_GETFD);
        if (flags == -1 ||
            fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) == -1) {
            _exit(126);
        }

        extern char **environ;
        char* argv[] = {const_cast<char*>(exe.c_str()),
                        const_cast<char*>("-c"),
                        const_cast<char*>("echo original"), nullptr};
        fexecve(fd, argv, environ);
        _exit(127);
    }

    close(pipefd[1]);
    char buffer[64] = {};
    ssize_t n = read(pipefd[0], buffer, sizeof(buffer) - 1);
    close(pipefd[0]);
    int status = 0;
    ASSERT_TRUE(waitpid(pid, &status, 0) == pid);
    close(fd);

    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQUAL(WEXITSTATUS(status), 0);
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(std::string(buffer, static_cast<size_t>(n)) == "original\n");
    return true;
}

bool test_config_path_trust() {
    Voix::FileUtils fu;
    ASSERT_TRUE(fu.is_trusted_config_path("/etc/passwd"));
    ASSERT_TRUE(!fu.is_trusted_config_path("relative.conf"));
    ASSERT_TRUE(!fu.is_trusted_config_path("/tmp/attacker.conf"));
    ASSERT_TRUE(!fu.is_trusted_config_path("/etc/../tmp/attacker.conf"));
    return true;
}

void register_file_utils_tests(TestRunner& runner) {
    runner.add_test("test_file_exists", test_file_exists);
    runner.add_test("test_read_file_success", test_read_file_success);
    runner.add_test("test_read_file_not_found", test_read_file_not_found);
    runner.add_test("test_read_file_empty", test_read_file_empty);
    runner.add_test("test_resolve_command_empty", test_resolve_command_empty);
    runner.add_test("test_resolve_command_absolute_nonexistent", test_resolve_command_absolute_nonexistent);
    runner.add_test("test_resolve_command_not_in_path", test_resolve_command_not_in_path);
    runner.add_test("test_resolve_command_rejects_group_writable", test_resolve_command_rejects_group_writable);
    runner.add_test("test_secure_read_write_roundtrip", test_secure_read_write_roundtrip);
    runner.add_test("test_secure_io_rejects_symlink", test_secure_io_rejects_symlink);
    runner.add_test("test_private_directory_enforced", test_private_directory_enforced);
    runner.add_test("test_resolve_executable_rejects_user_owned_by_default",
                    test_resolve_executable_rejects_user_owned_by_default);
    runner.add_test("test_resolve_executable_canonicalizes_symlink",
                    test_resolve_executable_canonicalizes_symlink);
    runner.add_test("test_executable_replacement_is_pinned",
                    test_executable_replacement_is_pinned);
    runner.add_test("test_config_path_trust", test_config_path_trust);
}
