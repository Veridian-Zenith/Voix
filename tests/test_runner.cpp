#include "test_assert.hpp"
#include "../include/file_utils.hpp"
#include "../include/logger.hpp"
#include "../include/security.hpp"
#include "../include/config.hpp"
#include "../include/permission_checker.hpp"
#include "../include/system_identity.hpp"
#include "../include/command.hpp"
#include "../include/system_utils.hpp"
#include <fstream>
#include <filesystem>
#include <memory>
#include <cstdlib>
#include <chrono>
#include <regex>

class ScopedTempFile {
public:
    explicit ScopedTempFile(std::filesystem::path path) : path_(std::move(path)) {}
    ~ScopedTempFile() {
        std::error_code ec;
        std::filesystem::remove(path_, ec);
    }
    std::filesystem::path path() const { return path_; }
private:
    std::filesystem::path path_;
};

class MockIdentity : public Voix::IIdentity {
public:
    struct MockUser {
        std::string name;
        uid_t uid;
        gid_t gid;
        std::vector<gid_t> groups;
    };
    std::vector<MockUser> users;
    std::string current_user;
    uid_t current_uid;
    std::vector<gid_t> current_groups;

    std::optional<Voix::UserIdentity> get_user_by_name(const std::string& username) const override {
        for (const auto& u : users) {
            if (u.name == username) return Voix::UserIdentity{u.name, u.uid, u.gid, u.groups, "/home/" + u.name, "/bin/bash"};
        }
        return std::nullopt;
    }
    std::optional<Voix::UserIdentity> get_user_by_uid(uid_t uid) const override {
        for (const auto& u : users) {
            if (u.uid == uid) return Voix::UserIdentity{u.name, u.uid, u.gid, u.groups, "/home/" + u.name, "/bin/bash"};
        }
        return std::nullopt;
    }
    std::string get_current_username() const override { return current_user; }
    uid_t get_current_uid() const override { return current_uid; }
    std::vector<gid_t> get_current_groups() const override { return current_groups; }
};

bool test_permission_checker_permit_allowed() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"alice", 1000, 1000, {1000, 4}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000, 4};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();
    
    // Create a dummy config file for testing
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_perm.conf";
    ScopedTempFile cleanup_guard(config_path);
    std::ofstream outfile(config_path);
    outfile << "acl:\n  user:\n    1000:\n      - action: permit\n        command: ls\n";
    outfile.close();
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);
    auto rule = checker.permit("ls", {}, 0);
    ASSERT_TRUE(rule.has_value());
    ASSERT_EQUAL(static_cast<int>(rule->action), static_cast<int>(Voix::Rule::Action::PERMIT));

    return true;
}

bool test_permission_checker_permit_denied() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"bob", 1001, 1001, {1001, 4}}};
    mock_id->current_user = "bob";
    mock_id->current_uid = 1001;
    mock_id->current_groups = {1001, 4};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();
    
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_perm_denied.conf";
    ScopedTempFile cleanup_guard(config_path);
    std::ofstream outfile(config_path);
    outfile << "acl:\n  user:\n    alice:\n      - action: permit\n        command: ls\n";
    outfile.close();
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);
    auto rule = checker.permit("ls", {}, 0);
    ASSERT_TRUE(!rule.has_value());

    return true;
}

bool test_config_load_valid() {
    std::string config_path = "test_voix.conf";
    std::ofstream outfile(config_path);
    outfile << "core:\n  paths: [/bin, /usr/bin]\n  sanctuary: /tmp/voix_test\n";
    outfile.close();

    Voix::Config config;
    ASSERT_TRUE(config.load(config_path, false));
    ASSERT_EQUAL(config.getSanctuary(), "/tmp/voix_test");
    ASSERT_EQUAL(config.getPath(), "/bin:/usr/bin");

    std::filesystem::remove(config_path);
    return true;
}

bool test_config_load_invalid_yaml() {
    std::string config_path = "invalid_voix.conf";
    std::ofstream outfile(config_path);
    outfile << "core: [this is not valid yaml for the expected structure"; 
    outfile.close();

    Voix::Config config;
    ASSERT_TRUE(!config.load(config_path, false));

    std::filesystem::remove(config_path);
    return true;
}

bool test_config_load_nonexistent() {
    Voix::Config config;
    ASSERT_TRUE(!config.load("this_file_does_not_exist.conf", false));
    return true;
}

bool test_security_validate_user_valid() {
    auto identity = std::make_shared<MockIdentity>();
    identity->users.push_back({"root", 0, 0, {0}});
    identity->current_user = "root";

    Voix::Security security(identity);
    ASSERT_TRUE(security.validateUser("root"));
    return true;
}

bool test_security_validate_user_invalid() {
    Voix::Security security;
    ASSERT_TRUE(!security.validateUser("non_existent_user_9999"));
    return true;
}

bool test_security_validate_user_too_long() {
    Voix::Security security;
    std::string long_user(33, 'a');
    ASSERT_TRUE(!security.validateUser(long_user));
    return true;
}

bool test_security_validate_user_bad_chars() {
    Voix::Security security;
    ASSERT_TRUE(!security.validateUser("user;rm -rf /"));
    ASSERT_TRUE(!security.validateUser("user name"));
    return true;
}

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

bool test_security_safe_path() {
    Voix::Security security;
    ASSERT_TRUE(security.isSafePath("/tmp/test"));
    ASSERT_TRUE(!security.isSafePath("/etc/shadow"));
    ASSERT_TRUE(!security.isSafePath("/etc/voix.conf"));
    return true;
}

bool test_security_catastrophic_command() {
    Voix::Security security;
    Voix::Config config;
    std::vector<std::string> args = {"-rf", "/"};
    ASSERT_TRUE(security.isCatastrophicCommand("rm", args, config));

    std::vector<std::string> safe_args = {"-l"};
    ASSERT_TRUE(!security.isCatastrophicCommand("ls", safe_args, config));
    return true;
}

// ============================================================
// Command tests
// ============================================================

bool test_command_resolve_profile_matrix() {
    // alpm is the only unconfined target; both named profiles are defined.
    const char* cfg =
        "core:\n"
        "  unconfined_targets:\n"
        "    - alpm\n"
        "security:\n"
        "  profiles:\n"
        "    restricted:\n"
        "      retain_full_capabilities: false\n"
        "      enable_seccomp: true\n"
        "      enable_resource_limits: true\n"
        "      scrub_environment: true\n"
        "    privileged:\n"
        "      retain_full_capabilities: true\n"
        "      enable_seccomp: false\n"
        "      enable_resource_limits: false\n"
        "      scrub_environment: false\n";
    std::filesystem::path cfg_path =
        std::filesystem::temp_directory_path() / "test_resolve_profile.yml";
    ScopedTempFile cleanup(cfg_path);
    {
        std::ofstream out(cfg_path);
        out << cfg;
    }
    Voix::Config config;
    ASSERT_TRUE(config.load(cfg_path.string(), false));

    Voix::Rule no_profile;
    Voix::Rule privileged_profile;
    privileged_profile.profile = "privileged";
    Voix::Rule restricted_profile;
    restricted_profile.profile = "restricted";

    // 1. alpm, no profile -> unconfined "system" profile (full env).
    auto p_alpm = Voix::Command::resolve_profile(config, no_profile, "alpm");
    ASSERT_TRUE(p_alpm.retain_full_capabilities);
    ASSERT_TRUE(!p_alpm.enable_seccomp);
    ASSERT_TRUE(!p_alpm.enable_resource_limits);
    ASSERT_TRUE(!p_alpm.scrub_environment);
    ASSERT_TRUE(p_alpm.preserve_full_environment);

    // 2. root, no profile -> safe restricted default.
    auto p_root = Voix::Command::resolve_profile(config, no_profile, "root");
    ASSERT_TRUE(!p_root.retain_full_capabilities);
    ASSERT_TRUE(p_root.enable_seccomp);
    ASSERT_TRUE(p_root.enable_resource_limits);
    ASSERT_TRUE(p_root.scrub_environment);
    ASSERT_TRUE(!p_root.preserve_full_environment);

    // 3. root with explicit privileged profile -> that profile is honored.
    auto p_priv = Voix::Command::resolve_profile(config, privileged_profile, "root");
    ASSERT_TRUE(p_priv.retain_full_capabilities);
    ASSERT_TRUE(!p_priv.enable_seccomp);
    ASSERT_TRUE(!p_priv.preserve_full_environment); // root is not unconfined

    // 4. alpm with explicit restricted profile -> confinement honored, but the
    //    unconfined target still keeps its full environment.
    auto p_alpm_restr = Voix::Command::resolve_profile(config, restricted_profile, "alpm");
    ASSERT_TRUE(!p_alpm_restr.retain_full_capabilities);
    ASSERT_TRUE(p_alpm_restr.enable_seccomp);
    ASSERT_TRUE(p_alpm_restr.preserve_full_environment);

    return true;
}

bool test_command_build_string_simple() {
    Voix::Command cmd;
    std::string result = cmd.buildCommandString("ls", {"-la"}, "root");
    ASSERT_EQUAL(result, std::string("'ls' '-la'"));
    return true;
}

bool test_command_build_string_non_root_user() {
    Voix::Command cmd;
    std::string result = cmd.buildCommandString("cat", {"/etc/hostname"}, "alice");
    ASSERT_EQUAL(result, std::string("su - 'alice' -c ''\\''cat'\\'' '\\''/etc/hostname'\\'''"));
    return true;
}

bool test_command_build_string_no_args() {
    Voix::Command cmd;
    std::string result = cmd.buildCommandString("whoami", {}, "root");
    ASSERT_EQUAL(result, std::string("'whoami'"));
    return true;
}

bool test_command_build_string_multiple_args() {
    Voix::Command cmd;
    std::string result = cmd.buildCommandString("cp", {"-r", "/src", "/dst"}, "root");
    ASSERT_EQUAL(result, std::string("'cp' '-r' '/src' '/dst'"));
    return true;
}

bool test_command_build_string_empty_user() {
    Voix::Command cmd;
    std::string result = cmd.buildCommandString("ls", {"-l"}, "");
    ASSERT_EQUAL(result, std::string("'ls' '-l'"));
    return true;
}

// ============================================================
// Logger tests
// ============================================================

bool test_logger_timestamp_format() {
    Voix::Logger logger;
    std::string ts = logger.getTimestamp();
    // Timestamp should be in YYYY-MM-DD HH:MM:SS format
    ASSERT_TRUE(ts.length() >= 19);
    ASSERT_EQUAL(ts[4], '-');
    ASSERT_EQUAL(ts[7], '-');
    ASSERT_EQUAL(ts[10], ' ');
    ASSERT_EQUAL(ts[13], ':');
    ASSERT_EQUAL(ts[16], ':');
    return true;
}

bool test_logger_timestamp_current_year() {
    Voix::Logger logger;
    std::string ts = logger.getTimestamp();
    // Year should be the current year or later
    auto now = std::chrono::system_clock::now();
    auto today = std::chrono::year_month_day{std::chrono::floor<std::chrono::days>(now)};
    int current_year = static_cast<int>(today.year());
    int year = std::stoi(ts.substr(0, 4));
    ASSERT_TRUE(year >= current_year);
    return true;
}

bool test_logger_log_does_not_crash() {
    // Logger::suppress_stderr is already true in tests
    Voix::Logger logger;
    // This should not throw or crash
    logger.log("INFO", "test message");
    logger.log("ERROR", "error message");
    logger.log("WARN", "warning message");
    return true;
}

bool test_logger_log_empty_message() {
    Voix::Logger logger;
    // Should handle empty strings gracefully
    logger.log("", "");
    logger.log("INFO", "");
    logger.log("", "some message");
    return true;
}

// ============================================================
// FileUtils tests - readFile / writeFile
// ============================================================

bool test_file_utils_read_file_success() {
    Voix::FileUtils file_utils;
    std::filesystem::path test_dir = std::filesystem::temp_directory_path() / "voix_test_read";
    std::filesystem::path test_file = test_dir / "readable.txt";
    std::filesystem::create_directories(test_dir);
    ScopedTempFile dir_guard(test_dir);

    {
        std::ofstream out(test_file);
        out << "hello world";
    }

    auto result = file_utils.readFile(test_file);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQUAL(result.value(), std::string("hello world"));

    std::filesystem::remove_all(test_dir);
    return true;
}

bool test_file_utils_read_file_not_found() {
    Voix::FileUtils file_utils;
    auto result = file_utils.readFile("/tmp/voix_nonexistent_file_xyz.txt");
    ASSERT_TRUE(!result.has_value());
    ASSERT_EQUAL(static_cast<int>(result.error()), static_cast<int>(Voix::FileError::NotFound));
    return true;
}

bool test_file_utils_read_file_empty() {
    Voix::FileUtils file_utils;
    std::filesystem::path test_dir = std::filesystem::temp_directory_path() / "voix_test_read_empty";
    std::filesystem::path test_file = test_dir / "empty.txt";
    std::filesystem::create_directories(test_dir);

    {
        std::ofstream out(test_file);
        // Write nothing
    }

    auto result = file_utils.readFile(test_file);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQUAL(result.value(), std::string(""));

    std::filesystem::remove_all(test_dir);
    return true;
}

bool test_file_utils_write_file_success() {
    Voix::FileUtils file_utils;
    std::filesystem::path test_dir = std::filesystem::temp_directory_path() / "voix_test_write";
    std::filesystem::path test_file = test_dir / "writable.txt";
    std::filesystem::create_directories(test_dir);

    auto result = file_utils.writeFile(test_file, "test content");
    ASSERT_TRUE(result.has_value());

    // Verify content was written
    auto read_result = file_utils.readFile(test_file);
    ASSERT_TRUE(read_result.has_value());
    ASSERT_EQUAL(read_result.value(), std::string("test content"));

    std::filesystem::remove_all(test_dir);
    return true;
}

bool test_file_utils_write_file_overwrite() {
    Voix::FileUtils file_utils;
    std::filesystem::path test_dir = std::filesystem::temp_directory_path() / "voix_test_overwrite";
    std::filesystem::path test_file = test_dir / "overwrite.txt";
    std::filesystem::create_directories(test_dir);

    (void)file_utils.writeFile(test_file, "original");
    (void)file_utils.writeFile(test_file, "replaced");

    auto result = file_utils.readFile(test_file);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQUAL(result.value(), std::string("replaced"));

    std::filesystem::remove_all(test_dir);
    return true;
}

bool test_file_utils_write_file_invalid_path() {
    Voix::FileUtils file_utils;
    auto result = file_utils.writeFile("/nonexistent_dir_xyz/file.txt", "content");
    ASSERT_TRUE(!result.has_value());
    return true;
}

// ============================================================
// FileUtils tests - resolve_command
// ============================================================

bool test_file_utils_resolve_command_empty() {
    Voix::FileUtils file_utils;
    std::string result = file_utils.resolve_command({"", "/usr/bin:/bin"});
    ASSERT_EQUAL(result, std::string(""));
    return true;
}

bool test_file_utils_resolve_command_absolute_nonexistent() {
    Voix::FileUtils file_utils;
    std::string result = file_utils.resolve_command({"/nonexistent/binary", "/usr/bin"});
    ASSERT_EQUAL(result, std::string(""));
    return true;
}

bool test_file_utils_resolve_command_not_in_path() {
    Voix::FileUtils file_utils;
    std::string result = file_utils.resolve_command({"totally_fake_command_xyz123", "/usr/bin:/bin"});
    ASSERT_EQUAL(result, std::string(""));
    return true;
}

// ============================================================
// SystemUtils tests
// ============================================================

bool test_system_utils_get_uid_by_name_root() {
    auto uid = Voix::SystemUtils::getUidByName("root");
    ASSERT_TRUE(uid.has_value());
    ASSERT_EQUAL(uid.value(), static_cast<uid_t>(0));
    return true;
}

bool test_system_utils_get_uid_by_name_nonexistent() {
    auto uid = Voix::SystemUtils::getUidByName("nonexistent_user_xyz_999");
    ASSERT_TRUE(!uid.has_value());
    return true;
}

bool test_system_utils_get_gid_by_name_root() {
    auto gid = Voix::SystemUtils::getGidByName("root");
    ASSERT_TRUE(gid.has_value());
    ASSERT_EQUAL(gid.value(), static_cast<gid_t>(0));
    return true;
}

bool test_system_utils_get_gid_by_name_nonexistent() {
    auto gid = Voix::SystemUtils::getGidByName("nonexistent_group_xyz_999");
    ASSERT_TRUE(!gid.has_value());
    return true;
}

bool test_system_utils_set_environment() {
    Voix::SystemUtils sys_utils;
    std::vector<std::string> env_vars = {"VOIX_TEST_VAR=hello_world"};
    sys_utils.setEnvironment(env_vars);

    const char* val = std::getenv("VOIX_TEST_VAR");
    ASSERT_TRUE(val != nullptr);
    ASSERT_EQUAL(std::string(val), std::string("hello_world"));

    // Clean up
    unsetenv("VOIX_TEST_VAR");
    return true;
}

bool test_system_utils_set_environment_multiple() {
    Voix::SystemUtils sys_utils;
    std::vector<std::string> env_vars = {
        "VOIX_TEST_A=alpha",
        "VOIX_TEST_B=beta",
        "VOIX_TEST_C=gamma"
    };
    sys_utils.setEnvironment(env_vars);

    const char* env_a = std::getenv("VOIX_TEST_A");
    const char* env_b = std::getenv("VOIX_TEST_B");
    const char* env_c = std::getenv("VOIX_TEST_C");
    ASSERT_TRUE(env_a != nullptr);
    ASSERT_TRUE(env_b != nullptr);
    ASSERT_TRUE(env_c != nullptr);
    ASSERT_EQUAL(std::string(env_a), std::string("alpha"));
    ASSERT_EQUAL(std::string(env_b), std::string("beta"));
    ASSERT_EQUAL(std::string(env_c), std::string("gamma"));

    unsetenv("VOIX_TEST_A");
    unsetenv("VOIX_TEST_B");
    unsetenv("VOIX_TEST_C");
    return true;
}

bool test_system_utils_set_environment_overwrite() {
    Voix::SystemUtils sys_utils;
    setenv("VOIX_TEST_OVERWRITE", "original", 1);

    std::vector<std::string> env_vars = {"VOIX_TEST_OVERWRITE=updated"};
    sys_utils.setEnvironment(env_vars);

    ASSERT_EQUAL(std::string(std::getenv("VOIX_TEST_OVERWRITE")), std::string("updated"));

    unsetenv("VOIX_TEST_OVERWRITE");
    return true;
}

bool test_system_utils_set_environment_empty_value() {
    Voix::SystemUtils sys_utils;
    std::vector<std::string> env_vars = {"VOIX_TEST_EMPTY="};
    sys_utils.setEnvironment(env_vars);

    const char* val = std::getenv("VOIX_TEST_EMPTY");
    ASSERT_TRUE(val != nullptr);
    ASSERT_EQUAL(std::string(val), std::string(""));

    unsetenv("VOIX_TEST_EMPTY");
    return true;
}

bool test_system_utils_set_environment_no_equals() {
    Voix::SystemUtils sys_utils;
    // Strings without '=' should be silently ignored
    std::vector<std::string> env_vars = {"NOEQUALSIGN"};
    sys_utils.setEnvironment(env_vars);
    // Should not crash; variable should not be set
    const char* val = std::getenv("NOEQUALSIGN");
    ASSERT_TRUE(val == nullptr);
    return true;
}

// ============================================================
// Config tests - additional coverage
// ============================================================

bool test_config_get_rules_empty() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_empty_rules.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin]\n  sanctuary: /tmp\n";
    }
    config.load(config_path.string(), false);
    auto rules = config.getRules();
    ASSERT_EQUAL(static_cast<int>(rules.size()), 0);
    return true;
}

bool test_config_validate_after_load() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_validate.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin, /usr/bin]\n  sanctuary: /tmp\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));
    // validate() checks schema and path permissions - without root, path check may fail
    // but at least it should not crash
    config.validate();
    return true;
}

bool test_config_blocklist() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_blocklist.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin]\n  sanctuary: /tmp\nsecurity:\n  blocklist:\n    - /bin/sh\n    - /bin/bash\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));

    const auto& blocklist = config.get_blocklist();
    ASSERT_TRUE(blocklist.size() >= 2);

    bool found_sh = false;
    bool found_bash = false;
    for (const auto& item : blocklist) {
        if (item == "/bin/sh") found_sh = true;
        if (item == "/bin/bash") found_bash = true;
    }
    ASSERT_TRUE(found_sh);
    ASSERT_TRUE(found_bash);
    return true;
}

bool test_config_seccomp_default_enabled() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_seccomp.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin]\n  sanctuary: /tmp\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));
    ASSERT_TRUE(config.is_seccomp_enabled());
    return true;
}

// ============================================================
// Security tests - additional coverage
// ============================================================

bool test_security_safe_path_traversal() {
    Voix::Security security;
    ASSERT_TRUE(!security.isSafePath("/tmp/../etc/shadow"));
    ASSERT_TRUE(!security.isSafePath("/home/user/../../etc/shadow"));
    return true;
}

bool test_security_safe_path_valid_paths() {
    Voix::Security security;
    ASSERT_TRUE(security.isSafePath("/usr/bin/ls"));
    ASSERT_TRUE(security.isSafePath("/home/user/documents"));
    ASSERT_TRUE(security.isSafePath("/var/log/syslog"));
    return true;
}

bool test_security_safe_path_root_forbidden() {
    Voix::Security security;
    ASSERT_TRUE(!security.isSafePath("/root"));
    ASSERT_TRUE(!security.isSafePath("/root/somefile"));
    return true;
}

bool test_security_catastrophic_rm_variants() {
    Voix::Security security;
    Voix::Config config;

    // rm -rf / with separate flags
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-r", "-f", "/"}, config));
    // rm -fr /
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-fr", "/"}, config));
    // rm -rf /*
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-rf", "/*"}, config));
    // /bin/rm should also be caught
    ASSERT_TRUE(security.isCatastrophicCommand("/bin/rm", {"-rf", "/"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/usr/bin/rm", {"-rf", "/"}, config));

    // Safe rm commands should not be catastrophic
    ASSERT_TRUE(!security.isCatastrophicCommand("rm", {"-rf", "/tmp/safe_dir"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("rm", {"file.txt"}, config));
    return true;
}

bool test_security_catastrophic_blocklist() {
    auto identity = std::make_shared<MockIdentity>();
    identity->users = {{"root", 0, 0, {0}}};
    identity->current_user = "root";

    Voix::Security security(identity);
    Voix::Config config;

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_cat_blocklist.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin]\n  sanctuary: /tmp\nsecurity:\n  blocklist:\n    - /bin/sh\n";
    }
    config.load(config_path.string(), false);

    ASSERT_TRUE(security.isCatastrophicCommand("/bin/sh", {}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("/bin/ls", {}, config));
    return true;
}

bool test_security_catastrophic_dd() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(security.isCatastrophicCommand("dd", {"if=/dev/zero", "of=/dev/sda", "bs=1M"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("dd", {"if=/dev/zero", "of=/dev/nvme0n1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/bin/dd", {"if=/dev/zero", "of=/dev/sdb"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/usr/bin/dd", {"if=/dev/zero", "of=/dev/nvme1n1"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("dd", {"if=/dev/zero", "of=disk.img"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("dd", {"--help"}, config));
    return true;
}

bool test_security_catastrophic_mkfs() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(security.isCatastrophicCommand("mkfs.ext4", {"/dev/sda1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("mkfs.btrfs", {"/dev/sdb1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("mkfs", {"-t", "ext4", "/dev/sdc1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/sbin/mkfs.xfs", {"/dev/sdd1"}, config));
    return true;
}

bool test_security_catastrophic_partition_tools() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(security.isCatastrophicCommand("fdisk", {"/dev/sda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/sbin/fdisk", {"/dev/sda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("parted", {"/dev/sda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("wipe", {"-a", "/dev/sdb"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/usr/bin/shred", {"/dev/sdc"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("shred", {"/etc/shadow"}, config));
    return true;
}

bool test_security_catastrophic_safe_commands() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(!security.isCatastrophicCommand("mount", {"/dev/sda1", "/mnt"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("lsblk", {}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("blkid", {"/dev/sda1"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("systemctl", {"start", "nginx"}, config));
    return true;
}

bool test_security_validate_user_underscore_hyphen() {
    auto identity = std::make_shared<MockIdentity>();
    identity->users = {{"test-user", 1000, 1000, {1000}}, {"test_user", 1001, 1001, {1001}}};
    identity->current_user = "test-user";

    Voix::Security security(identity);
    ASSERT_TRUE(security.validateUser("test-user"));
    ASSERT_TRUE(security.validateUser("test_user"));
    return true;
}

bool test_security_validate_user_empty() {
    Voix::Security security;
    ASSERT_TRUE(!security.validateUser(""));
    return true;
}

bool test_security_get_current_user() {
    auto identity = std::make_shared<MockIdentity>();
    identity->current_user = "testuser";
    identity->current_uid = 1000;

    Voix::Security security(identity);
    ASSERT_EQUAL(security.getCurrentUser(), std::string("testuser"));
    ASSERT_EQUAL(security.get_current_uid(), static_cast<uid_t>(1000));
    return true;
}

// ============================================================
// PermissionChecker tests - additional coverage
// ============================================================

bool test_permission_checker_group_rule() {
    auto mock_id = std::make_shared<MockIdentity>();
    // GID 0 = root group, which exists on all systems
    mock_id->users = {{"alice", 1000, 1000, {1000, 0}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000, 0};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_perm_group.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        // Use "root" group name which maps to GID 0
        out << "acl:\n  group:\n    root:\n      - action: permit\n";
    }
    config->load(config_path.string(), false);

    // Verify that 'root' group name is resolved to GID 0
    const auto& loaded_rules = config->getRules();
    ASSERT_TRUE(loaded_rules.size() > 0);
    ASSERT_TRUE(loaded_rules[0].ident_gid.has_value());
    ASSERT_EQUAL(loaded_rules[0].ident_gid.value(), static_cast<gid_t>(0));

    Voix::PermissionChecker checker(security, config);
    auto rule = checker.permit("anything", {}, 0);
    ASSERT_TRUE(rule.has_value());
    return true;
}

bool test_permission_checker_deny_rule() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"alice", 1000, 1000, {1000}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_perm_deny.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "acl:\n  user:\n    1000:\n      - action: deny\n        command: rm\n";
    }
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);
    auto rule = checker.permit("rm", {}, 0);
    ASSERT_TRUE(!rule.has_value());
    return true;
}

bool test_permission_checker_command_specific() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"alice", 1000, 1000, {1000}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_perm_cmd.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "acl:\n  user:\n    1000:\n      - action: permit\n        command: ls\n";
    }
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);
    // ls should be permitted
    auto rule_ls = checker.permit("ls", {}, 0);
    ASSERT_TRUE(rule_ls.has_value());
    // cat should not match
    auto rule_cat = checker.permit("cat", {}, 0);
    ASSERT_TRUE(!rule_cat.has_value());
    return true;
}

// ============================================================
// Config::validate() tests
// ============================================================

bool test_config_validate_valid_config() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_validate_valid.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin, /usr/bin]\n  sanctuary: /tmp\n"
            << "acl:\n  user:\n    1000:\n      - action: permit\n        command: ls\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));
    ASSERT_TRUE(config.validate());
    return true;
}

bool test_config_validate_relative_path() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_validate_relpath.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [bin, /usr/bin]\n  sanctuary: /tmp\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));
    ASSERT_TRUE(!config.validate());
    return true;
}

bool test_config_validate_empty_sanctuary() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_validate_emptysanc.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin]\n  sanctuary: \"\"\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));
    ASSERT_TRUE(!config.validate());
    return true;
}

// ============================================================
// PermissionChecker::list_permitted_rules() tests
// ============================================================

bool test_permission_checker_list_permitted_rules() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"alice", 1000, 1000, {1000}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_list_rules.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "acl:\n  user:\n    1000:\n"
            << "      - action: permit\n        command: ls\n"
            << "      - action: permit\n        command: cat\n"
            << "      - action: deny\n        command: rm\n";
    }
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);
    auto rules = checker.list_permitted_rules();
    // Should have 2 permit rules (ls and cat), not the deny rule
    ASSERT_EQUAL(static_cast<int>(rules.size()), 2);
    ASSERT_EQUAL(rules[0].cmd, std::string("ls"));
    ASSERT_EQUAL(rules[1].cmd, std::string("cat"));
    return true;
}

bool test_permission_checker_list_permitted_rules_empty() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"bob", 2000, 2000, {2000}}};
    mock_id->current_user = "bob";
    mock_id->current_uid = 2000;
    mock_id->current_groups = {2000};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_list_empty.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "acl:\n  user:\n    1000:\n      - action: permit\n        command: ls\n";
    }
    ASSERT_TRUE(config->load(config_path.string(), false));

    Voix::PermissionChecker checker(security, config);
    auto rules = checker.list_permitted_rules();
    ASSERT_EQUAL(static_cast<int>(rules.size()), 0);
    return true;
}

bool test_config_unconfined_targets() {
    Voix::Config config;
    // Default should contain only the package-manager target (alpm).
    ASSERT_TRUE(config.is_unconfined_target("alpm"));
    ASSERT_TRUE(!config.is_unconfined_target("root"));
    ASSERT_TRUE(!config.is_unconfined_target("guest"));

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_unconfined_targets.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  unconfined_targets:\n    - admin\n    - operator\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));
    ASSERT_TRUE(config.is_unconfined_target("admin"));
    ASSERT_TRUE(config.is_unconfined_target("operator"));
    ASSERT_TRUE(!config.is_unconfined_target("root"));
    ASSERT_TRUE(!config.is_unconfined_target("alpm"));

    return true;
}

int main() {
    Voix::Logger::suppress_stderr = true;
    TestRunner runner;

    // Existing tests
    runner.add_test("test_permission_checker_permit_allowed", test_permission_checker_permit_allowed);
    runner.add_test("test_permission_checker_permit_denied", test_permission_checker_permit_denied);
    runner.add_test("test_config_load_valid", test_config_load_valid);
    runner.add_test("test_config_load_invalid_yaml", test_config_load_invalid_yaml);
    runner.add_test("test_config_load_nonexistent", test_config_load_nonexistent);
    runner.add_test("test_security_validate_user_valid", test_security_validate_user_valid);
    runner.add_test("test_security_validate_user_invalid", test_security_validate_user_invalid);
    runner.add_test("test_security_validate_user_too_long", test_security_validate_user_too_long);
    runner.add_test("test_security_validate_user_bad_chars", test_security_validate_user_bad_chars);
    runner.add_test("test_file_exists", test_file_exists);
    runner.add_test("test_security_safe_path", test_security_safe_path);
    runner.add_test("test_security_catastrophic_command", test_security_catastrophic_command);

    // New Command tests
    runner.add_test("test_command_build_string_simple", test_command_build_string_simple);
    runner.add_test("test_command_build_string_non_root_user", test_command_build_string_non_root_user);
    runner.add_test("test_command_build_string_no_args", test_command_build_string_no_args);
    runner.add_test("test_command_build_string_multiple_args", test_command_build_string_multiple_args);
    runner.add_test("test_command_build_string_empty_user", test_command_build_string_empty_user);

    // New Logger tests
    runner.add_test("test_logger_timestamp_format", test_logger_timestamp_format);
    runner.add_test("test_logger_timestamp_current_year", test_logger_timestamp_current_year);
    runner.add_test("test_logger_log_does_not_crash", test_logger_log_does_not_crash);
    runner.add_test("test_logger_log_empty_message", test_logger_log_empty_message);

    // New FileUtils tests - readFile/writeFile
    runner.add_test("test_file_utils_read_file_success", test_file_utils_read_file_success);
    runner.add_test("test_file_utils_read_file_not_found", test_file_utils_read_file_not_found);
    runner.add_test("test_file_utils_read_file_empty", test_file_utils_read_file_empty);
    runner.add_test("test_file_utils_write_file_success", test_file_utils_write_file_success);
    runner.add_test("test_file_utils_write_file_overwrite", test_file_utils_write_file_overwrite);
    runner.add_test("test_file_utils_write_file_invalid_path", test_file_utils_write_file_invalid_path);

    // New FileUtils tests - resolve_command
    runner.add_test("test_file_utils_resolve_command_empty", test_file_utils_resolve_command_empty);
    runner.add_test("test_file_utils_resolve_command_absolute_nonexistent", test_file_utils_resolve_command_absolute_nonexistent);
    runner.add_test("test_file_utils_resolve_command_not_in_path", test_file_utils_resolve_command_not_in_path);

    // New SystemUtils tests
    runner.add_test("test_system_utils_get_uid_by_name_root", test_system_utils_get_uid_by_name_root);
    runner.add_test("test_system_utils_get_uid_by_name_nonexistent", test_system_utils_get_uid_by_name_nonexistent);
    runner.add_test("test_system_utils_get_gid_by_name_root", test_system_utils_get_gid_by_name_root);
    runner.add_test("test_system_utils_get_gid_by_name_nonexistent", test_system_utils_get_gid_by_name_nonexistent);
    runner.add_test("test_system_utils_set_environment", test_system_utils_set_environment);
    runner.add_test("test_system_utils_set_environment_multiple", test_system_utils_set_environment_multiple);
    runner.add_test("test_system_utils_set_environment_overwrite", test_system_utils_set_environment_overwrite);
    runner.add_test("test_system_utils_set_environment_empty_value", test_system_utils_set_environment_empty_value);
    runner.add_test("test_system_utils_set_environment_no_equals", test_system_utils_set_environment_no_equals);

    // New Config tests - additional coverage
    runner.add_test("test_config_get_rules_empty", test_config_get_rules_empty);
    runner.add_test("test_config_validate_after_load", test_config_validate_after_load);
    runner.add_test("test_config_blocklist", test_config_blocklist);
    runner.add_test("test_config_seccomp_default_enabled", test_config_seccomp_default_enabled);
    runner.add_test("test_config_unconfined_targets", test_config_unconfined_targets);

    // New Security tests - additional coverage
    runner.add_test("test_security_safe_path_traversal", test_security_safe_path_traversal);
    runner.add_test("test_security_safe_path_valid_paths", test_security_safe_path_valid_paths);
    runner.add_test("test_security_safe_path_root_forbidden", test_security_safe_path_root_forbidden);
    runner.add_test("test_security_catastrophic_rm_variants", test_security_catastrophic_rm_variants);
    runner.add_test("test_security_catastrophic_blocklist", test_security_catastrophic_blocklist);
    runner.add_test("test_security_catastrophic_dd", test_security_catastrophic_dd);
    runner.add_test("test_security_catastrophic_mkfs", test_security_catastrophic_mkfs);
    runner.add_test("test_security_catastrophic_partition_tools", test_security_catastrophic_partition_tools);
    runner.add_test("test_security_catastrophic_safe_commands", test_security_catastrophic_safe_commands);
    runner.add_test("test_security_validate_user_underscore_hyphen", test_security_validate_user_underscore_hyphen);
    runner.add_test("test_security_validate_user_empty", test_security_validate_user_empty);
    runner.add_test("test_security_get_current_user", test_security_get_current_user);

    // Profile-resolution matrix
    runner.add_test("test_command_resolve_profile_matrix", test_command_resolve_profile_matrix);

    // New PermissionChecker tests - additional coverage
    runner.add_test("test_permission_checker_group_rule", test_permission_checker_group_rule);
    runner.add_test("test_permission_checker_deny_rule", test_permission_checker_deny_rule);
    runner.add_test("test_permission_checker_command_specific", test_permission_checker_command_specific);

    // Config::validate() tests
    runner.add_test("test_config_validate_valid_config", test_config_validate_valid_config);
    runner.add_test("test_config_validate_relative_path", test_config_validate_relative_path);
    runner.add_test("test_config_validate_empty_sanctuary", test_config_validate_empty_sanctuary);

    // PermissionChecker::list_permitted_rules() tests
    runner.add_test("test_permission_checker_list_permitted_rules", test_permission_checker_list_permitted_rules);
    runner.add_test("test_permission_checker_list_permitted_rules_empty", test_permission_checker_list_permitted_rules_empty);

    return runner.run();
}
