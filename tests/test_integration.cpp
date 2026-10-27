/**
 * @file test_integration.cpp
 * @brief End-to-end execution tests.
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

/**
 * @file test_integration.cpp
 * @brief End-to-end tests through the real fork()/fexecve() path.
 *
 * The unit tests exercise resolution, environment construction, and policy
 * evaluation in isolation. These tests run the same code the daemon runs:
 * resolve -> open -> pin -> fork -> privilege transition -> FD scrub ->
 * kernel confinement -> fexecve, and observe the child's exit status.
 *
 * They run unprivileged by giving Command and FileUtils the current effective
 * UID as the trusted executable owner, and by using a target identity equal to
 * the test process (so setgid/setuid are no-ops and setgroups is skipped).
 */

#include "test_modules.hpp"
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <sys/wait.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

/// A private temporary directory for one test.
class ScopedTempDir {
public:
    ScopedTempDir() {
        std::string templ = (fs::temp_directory_path() / "voix-it-XXXXXX").string();
        if (mkdtemp(templ.data()) == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = templ;
    }
    ~ScopedTempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    const fs::path& path() const { return path_; }
    fs::path operator/(std::string_view name) const { return path_ / name; }

private:
    fs::path path_;
};

/// Copies a real binary into @p dest with mode 0755, owned by the caller.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
bool copy_executable(const fs::path& source, const fs::path& dest) {
    std::ifstream in(source, std::ios::binary);
    if (!in) return false;
    std::ofstream out(dest, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << in.rdbuf();
    out.close();
    if (!out) return false;
    std::error_code ec;
    fs::permissions(dest, fs::perms::owner_all | fs::perms::group_read |
                              fs::perms::group_exec | fs::perms::others_read |
                              fs::perms::others_exec,
                    fs::perm_options::replace, ec);
    return !ec;
}

/// Identity of the test process, so the privilege transition is a no-op.
Voix::UserIdentity self_identity() {
    return Voix::UserIdentity{"integration", geteuid(), getegid(), {},
                              "/tmp/voix-integration-home", "/bin/sh"};
}

/// Runs @p body with stdout redirected into a pipe and returns what it wrote.
/// The pipe is read after the body returns, so the body must not block on a
/// full pipe buffer (all callers here produce a handful of bytes).
std::string capture_stdout(const std::function<int()>& body, int* status_out) {
    int fds[2];
    if (pipe(fds) != 0) {
        if (status_out) *status_out = -1;
        return {};
    }

    const int saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout == -1) {
        close(fds[0]);
        close(fds[1]);
        if (status_out) *status_out = -1;
        return {};
    }
    std::fflush(stdout);
    if (dup2(fds[1], STDOUT_FILENO) == -1) {
        close(fds[0]);
        close(fds[1]);
        close(saved_stdout);
        if (status_out) *status_out = -1;
        return {};
    }
    close(fds[1]);

    const int status = body();

    std::fflush(stdout);
    if (dup2(saved_stdout, STDOUT_FILENO) == -1) {
        // Nothing useful to do; the test will fail on its own assertion.
    }
    close(saved_stdout);

    std::string output;
    char buffer[256];
    ssize_t n = 0;
    while ((n = read(fds[0], buffer, sizeof(buffer))) > 0) {
        output.append(buffer, static_cast<size_t>(n));
    }
    close(fds[0]);

    if (status_out) *status_out = status;
    return output;
}

/// Default configuration: no rules, no profiles, restricted defaults.
Voix::Config make_config() {
    Voix::Config config;
    return config;
}

} // namespace

bool test_integration_executes_and_propagates_exit_status() {
    ScopedTempDir dir;
    const fs::path prog = dir / "prog";
    ASSERT_TRUE(copy_executable("/bin/sh", prog));

    Voix::FileUtils file_utils(geteuid());
    auto info = file_utils.resolve_executable(prog.string(), "");
    ASSERT_TRUE(info.has_value());

    Voix::Command command(geteuid());
    Voix::Config config = make_config();
    Voix::CommandOptions options;
    Voix::Rule rule;

    // Exit status 42 must be propagated verbatim, not mapped onto one of
    // Voix's own sysexits codes.
    const int rc = command.execute(*info, {"-c", "exit 42"}, config, options,
                                   rule, self_identity());
    ASSERT_EQUAL(rc, 42);
    return true;
}

bool test_integration_toctou_replacement_is_refused() {
    ScopedTempDir dir;
    const fs::path prog = dir / "prog";
    ASSERT_TRUE(copy_executable("/bin/sh", prog));

    Voix::FileUtils file_utils(geteuid());
    auto info = file_utils.resolve_executable(prog.string(), "");
    ASSERT_TRUE(info.has_value());

    // Replace the validated path with a different inode between validation and
    // execution. A path-based exec would run the replacement; the pinned
    // descriptor must refuse it. Keep the original inode alive through a
    // hardlink so the filesystem cannot recycle its (dev, ino) pair.
    const fs::path original = dir / "original";
    ASSERT_EQUAL(link(prog.c_str(), original.c_str()), 0);
    ASSERT_EQUAL(unlink(prog.c_str()), 0);
    ASSERT_TRUE(copy_executable("/bin/false", prog));

    Voix::Command command(geteuid());
    Voix::Config config = make_config();
    Voix::CommandOptions options;
    Voix::Rule rule;

    const int rc = command.execute(*info, {}, config, options, rule,
                                   self_identity());
    ASSERT_EQUAL(rc, static_cast<int>(Voix::exit_status(Voix::ExitCode::NoExec)));
    return true;
}

bool test_integration_toctou_same_inode_still_runs() {
    // Control for the test above: without replacement the same setup runs.
    ScopedTempDir dir;
    const fs::path prog = dir / "prog";
    ASSERT_TRUE(copy_executable("/bin/sh", prog));

    Voix::FileUtils file_utils(geteuid());
    auto info = file_utils.resolve_executable(prog.string(), "");
    ASSERT_TRUE(info.has_value());

    Voix::Command command(geteuid());
    Voix::Config config = make_config();
    Voix::CommandOptions options;
    Voix::Rule rule;

    ASSERT_EQUAL(command.execute(*info, {"-c", "exit 0"}, config, options, rule,
                                 self_identity()),
                 0);
    return true;
}

bool test_integration_set_home_reaches_child() {
    ScopedTempDir dir;
    const fs::path prog = dir / "prog";
    ASSERT_TRUE(copy_executable("/bin/sh", prog));

    Voix::FileUtils file_utils(geteuid());
    auto info = file_utils.resolve_executable(prog.string(), "");
    ASSERT_TRUE(info.has_value());

    Voix::Command command(geteuid());
    Voix::Config config = make_config();
    Voix::CommandOptions options;
    options.set_home = true;
    Voix::Rule rule;

    Voix::UserIdentity target = self_identity();
    target.home_dir = "/tmp/voix-integration-home";

    int status = -1;
    const std::string output = capture_stdout(
        [&] {
            return command.execute(*info, {"-c", "printf %s \"$HOME\""}, config,
                                   options, rule, target);
        },
        &status);

    ASSERT_EQUAL(status, 0);
    ASSERT_EQUAL(output, std::string("/tmp/voix-integration-home"));
    return true;
}

bool test_integration_sanitized_environment_reaches_child() {
    // The child must not inherit the caller's environment when the profile
    // scrubs it: LD_PRELOAD is the classic loader-injection vector.
    ScopedTempDir dir;
    const fs::path prog = dir / "prog";
    ASSERT_TRUE(copy_executable("/bin/sh", prog));

    Voix::FileUtils file_utils(geteuid());
    auto info = file_utils.resolve_executable(prog.string(), "");
    ASSERT_TRUE(info.has_value());

    setenv("VOIX_INTEGRATION_SECRET", "leaked", 1);
    setenv("LD_PRELOAD", "/tmp/not-a-real-preload.so", 1);

    Voix::Command command(geteuid());
    Voix::Config config = make_config();
    Voix::CommandOptions options;
    Voix::Rule rule;

    int status = -1;
    const std::string output = capture_stdout(
        [&] {
            return command.execute(
                *info,
                {"-c",
                 "case \"${LD_PRELOAD:-}\" in *not-a-real-preload*) p=leaked;; "
                 "*) p=unset;; esac; "
                 "printf '%s|%s' \"${VOIX_INTEGRATION_SECRET:-unset}\" \"$p\""},
                config, options, rule, self_identity());
        },
        &status);

    unsetenv("VOIX_INTEGRATION_SECRET");
    unsetenv("LD_PRELOAD");

    ASSERT_EQUAL(status, 0);
    ASSERT_EQUAL(output, std::string("unset|unset"));
    return true;
}

bool test_integration_keepenv_reaches_child() {
    // Same probe as above, but with the rule's keepenv grant: the ordinary
    // variable survives while the dangerous one is still stripped.
    ScopedTempDir dir;
    const fs::path prog = dir / "prog";
    ASSERT_TRUE(copy_executable("/bin/sh", prog));

    Voix::FileUtils file_utils(geteuid());
    auto info = file_utils.resolve_executable(prog.string(), "");
    ASSERT_TRUE(info.has_value());

    setenv("VOIX_INTEGRATION_SECRET", "kept", 1);
    setenv("LD_PRELOAD", "/tmp/not-a-real-preload.so", 1);

    Voix::Command command(geteuid());
    Voix::Config config = make_config();
    Voix::CommandOptions options;
    options.preserve_env = true; // set from Rule::KEEPENV by Voix::execute
    Voix::Rule rule;

    int status = -1;
    const std::string output = capture_stdout(
        [&] {
            return command.execute(
                *info,
                {"-c",
                 "case \"${LD_PRELOAD:-}\" in *not-a-real-preload*) p=leaked;; "
                 "*) p=unset;; esac; "
                 "printf '%s|%s' \"${VOIX_INTEGRATION_SECRET:-unset}\" \"$p\""},
                config, options, rule, self_identity());
        },
        &status);

    unsetenv("VOIX_INTEGRATION_SECRET");
    unsetenv("LD_PRELOAD");

    ASSERT_EQUAL(status, 0);
    ASSERT_EQUAL(output, std::string("kept|unset"));
    return true;
}

bool test_integration_allowlist_mode_runs_real_command() {
    // End-to-end version of the seccomp unit test: the filter is applied in
    // the child after the privilege transition, and the target still runs.
    const fs::path ls = fs::exists("/bin/ls") ? fs::path("/bin/ls")
                                              : fs::path("/usr/bin/ls");
    ASSERT_TRUE(fs::exists(ls));

    Voix::FileUtils file_utils(0); // /bin/ls is root-owned
    auto info = file_utils.resolve_executable(ls.string(), "");
    ASSERT_TRUE(info.has_value());

    // Use the real configuration path so the profile parsing is covered too.
    ScopedTempDir dir;
    const fs::path config_path = dir / "allowlist.conf";
    {
        std::ofstream out(config_path);
        // validate() only needs an existing directory; the test's own temp
        // directory avoids depending on an installed /var/lib/voix.
        out << "core:\n  sanctuary: " << dir.path().string() << "\n"
            << "security:\n  profiles:\n    it-allowlist:\n"
            << "      seccomp_mode: allowlist\n";
    }
    Voix::Config config;
    ASSERT_TRUE(config.load(config_path.string(), false));
    ASSERT_TRUE(config.validate());

    Voix::Rule rule;
    rule.profile = "it-allowlist";

    Voix::Command command(0);
    Voix::CommandOptions options;

    int status = -1;
    capture_stdout(
        [&] {
            return command.execute(*info, {"--version"}, config, options, rule,
                                   self_identity());
        },
        &status);

    ASSERT_EQUAL(status, 0);
    return true;
}

bool test_integration_blacklist_mode_runs_real_command() {
    const fs::path ls = fs::exists("/bin/ls") ? fs::path("/bin/ls")
                                              : fs::path("/usr/bin/ls");
    ASSERT_TRUE(fs::exists(ls));

    Voix::FileUtils file_utils(0);
    auto info = file_utils.resolve_executable(ls.string(), "");
    ASSERT_TRUE(info.has_value());

    Voix::Config config = make_config();
    Voix::Rule rule;
    Voix::Command command(0);
    Voix::CommandOptions options;

    int status = -1;
    capture_stdout(
        [&] {
            return command.execute(*info, {"--version"}, config, options, rule,
                                   self_identity());
        },
        &status);

    ASSERT_EQUAL(status, 0);
    return true;
}

bool test_integration_acl_denial_never_executes() {
    // The permission checker runs before any process is created. A denied
    // command must not reach the fork/fexecve path at all.
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"alice", 1000, 1000, {1000}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    ScopedTempDir dir;
    const fs::path config_path = dir / "acl.conf";
    {
        std::ofstream out(config_path);
        out << "acl:\n  user:\n    1000:\n"
            << "      - action: permit\n"
            << "        command: /usr/bin/true\n";
    }
    ASSERT_TRUE(config->load(config_path.string(), false));

    Voix::PermissionChecker checker(security, config);
    ASSERT_TRUE(checker.permit("/usr/bin/true", {}, 0).has_value());
    ASSERT_TRUE(!checker.permit("/usr/bin/false", {}, 0).has_value());
    return true;
}

void register_integration_tests(TestRunner& runner) {
    runner.add_test("test_integration_executes_and_propagates_exit_status",
                    test_integration_executes_and_propagates_exit_status);
    runner.add_test("test_integration_toctou_replacement_is_refused",
                    test_integration_toctou_replacement_is_refused);
    runner.add_test("test_integration_toctou_same_inode_still_runs",
                    test_integration_toctou_same_inode_still_runs);
    runner.add_test("test_integration_set_home_reaches_child",
                    test_integration_set_home_reaches_child);
    runner.add_test("test_integration_sanitized_environment_reaches_child",
                    test_integration_sanitized_environment_reaches_child);
    runner.add_test("test_integration_keepenv_reaches_child",
                    test_integration_keepenv_reaches_child);
    runner.add_test("test_integration_allowlist_mode_runs_real_command",
                    test_integration_allowlist_mode_runs_real_command);
    runner.add_test("test_integration_blacklist_mode_runs_real_command",
                    test_integration_blacklist_mode_runs_real_command);
    runner.add_test("test_integration_acl_denial_never_executes",
                    test_integration_acl_denial_never_executes);
}
