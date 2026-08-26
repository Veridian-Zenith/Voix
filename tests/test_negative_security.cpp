/**
 * @file test_negative_security.cpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

/**
 * @file test_negative_security.cpp
 * @brief Negative security tests — attempt to bypass Voix defenses.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

#include "test_modules.hpp"

// 1. Catastrophic command detection: encoded/renamed paths
bool test_neg_catastrophic_encoded_paths() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(security.isCatastrophicCommand("/usr/bin/mkfs.ext4", {"/dev/sda1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/sbin/fdisk", {"/dev/sda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("mkfs", {"-t", "ext4", "/dev/sda1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("fdisk", {"/dev/sda"}, config));

    return true;
}

// 2. Catastrophic command detection: environment manipulation is irrelevant —
//    detection happens at the string level before any execution.
bool test_neg_catastrophic_env_manipulation() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(security.isCatastrophicCommand("/usr/bin/mkfs.ext4", {"/dev/sda1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/usr/bin/rm", {"-rf", "/"}, config));
    return true;
}

// 3. Catastrophic command detection: symlink bypass attempt
bool test_neg_catastrophic_symlink_bypass() {
    Voix::Security security;
    Voix::Config config;

    // A symlink named "safe" pointing to "rm" would bypass naive string
    // matching; basename matching catches the resolved execution path later,
    // while the literal name here must NOT be pre-blocked.
    ASSERT_TRUE(!security.isCatastrophicCommand("safe", {"-rf", "/"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/bin/rm", {"-rf", "/"}, config));

    return true;
}

// 4. Catastrophic command detection: traversal in arguments
bool test_neg_catastrophic_path_traversal_args() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(security.isCatastrophicCommand("dd", {"if=/dev/zero", "of=/dev/sda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-rf", "/"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("dd", {"if=/dev/zero", "of=/tmp/image.img"}, config));

    return true;
}

// 5./6. Config tampering: symlink and world-writable rejection
bool test_neg_config_symlink_rejection() {
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_symlink.conf";
    std::filesystem::path target_path = std::filesystem::temp_directory_path() / "test_symlink_target.conf";
    ScopedTempFile cleanup_config(config_path);
    ScopedTempFile cleanup_target(target_path);

    {
        std::ofstream out(target_path);
        out << "core:\n  paths: [/bin]\n  sanctuary: /tmp\n";
    }

    std::error_code ec;
    std::filesystem::create_symlink(target_path, config_path, ec);

    Voix::Config config;
    ASSERT_TRUE(!config.load(config_path.string(), true));

    return true;
}

bool test_neg_config_world_writable_rejection() {
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_worldwritable.conf";
    ScopedTempFile cleanup(config_path);

    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin]\n  sanctuary: /tmp\n";
    }

    std::filesystem::permissions(config_path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
        std::filesystem::perms::group_read | std::filesystem::perms::group_write |
        std::filesystem::perms::others_read | std::filesystem::perms::others_write,
        std::filesystem::perm_options::replace);

    // World-writable config fails the secure fd checks (uid/euid mismatch in
    // tests, write bits in production).
    Voix::Config config;
    ASSERT_TRUE(!config.load(config_path.string(), true));

    std::filesystem::permissions(config_path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);

    return true;
}

// 7. Permission bypass: -u with no matching target rule
bool test_neg_permission_no_target_bypass() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"testuser", 1000, 1000, {1000}}};
    mock_id->current_user = "testuser";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_neg_no_target.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "acl:\n  user:\n    1000:\n      - action: permit\n        command: ls\n";
    }
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);

    auto rule_root = checker.permit("ls", {}, 0);
    ASSERT_TRUE(rule_root.has_value());

    auto rule_other = checker.permit("ls", {}, 1001);
    ASSERT_TRUE(!rule_other.has_value());

    return true;
}

// 8. Permission bypass: group spoofing attempt
bool test_neg_permission_group_spoof() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"alice", 1000, 1000, {1000}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000};  // no wheel

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_neg_group_spoof.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "acl:\n  group:\n    wheel:\n      - action: permit\n";
    }
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);
    auto rule = checker.permit("anything", {}, 0);
    ASSERT_TRUE(!rule.has_value());

    return true;
}

// 9. Blocklist evasion attempts: whitespace/case variants
bool test_neg_blocklist_variants() {
    auto identity = std::make_shared<MockIdentity>();
    identity->users = {{"root", 0, 0, {0}}};
    identity->current_user = "root";

    Voix::Security security(identity);
    Voix::Config config;

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_neg_regex.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin]\n  sanctuary: /tmp\nsecurity:\n  blocklist:\n    - /bin/sh\n";
    }
    config.load(config_path.string(), false);

    ASSERT_TRUE(security.isCatastrophicCommand("/bin/sh ", {}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/bin/sh\t", {}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/bin/sh", {}, config));
    // Case differences do not match (case-sensitive by design)
    ASSERT_TRUE(!security.isCatastrophicCommand("/bin/SH", {}, config));

    return true;
}

// 10. Command injection metacharacters are inert (execv, no shell)
bool test_neg_command_injection_metachars() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(!security.isCatastrophicCommand("ls", {"; rm -rf /"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("cat", {"$(rm -rf /)"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("echo", {"`rm -rf /`"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("ls", {"| rm -rf /"}, config));

    return true;
}

// 11. Environment injection does not affect catastrophic detection
bool test_neg_environment_injection() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-rf", "/"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/bin/rm", {"-rf", "/"}, config));
    return true;
}

// 12. User validation: injection attempts
bool test_neg_validate_user_injection() {
    Voix::Security security;

    ASSERT_TRUE(!security.validateUser("root; rm -rf /"));
    ASSERT_TRUE(!security.validateUser("root' OR '1'='1"));
    ASSERT_TRUE(!security.validateUser("admin$(whoami)"));
    ASSERT_TRUE(!security.validateUser("admin`whoami`"));
    ASSERT_TRUE(!security.validateUser("admin|cat /etc/shadow"));
    ASSERT_TRUE(!security.validateUser("root\x00admin"));
    ASSERT_TRUE(!security.validateUser("r\u006ft"));

    return true;
}

void register_negative_security_tests(TestRunner& runner) {
    runner.add_test("test_neg_catastrophic_encoded_paths", test_neg_catastrophic_encoded_paths);
    runner.add_test("test_neg_catastrophic_env_manipulation", test_neg_catastrophic_env_manipulation);
    runner.add_test("test_neg_catastrophic_symlink_bypass", test_neg_catastrophic_symlink_bypass);
    runner.add_test("test_neg_catastrophic_path_traversal_args", test_neg_catastrophic_path_traversal_args);
    runner.add_test("test_neg_config_symlink_rejection", test_neg_config_symlink_rejection);
    runner.add_test("test_neg_config_world_writable_rejection", test_neg_config_world_writable_rejection);
    runner.add_test("test_neg_permission_no_target_bypass", test_neg_permission_no_target_bypass);
    runner.add_test("test_neg_permission_group_spoof", test_neg_permission_group_spoof);
    runner.add_test("test_neg_blocklist_variants", test_neg_blocklist_variants);
    runner.add_test("test_neg_command_injection_metachars", test_neg_command_injection_metachars);
    runner.add_test("test_neg_environment_injection", test_neg_environment_injection);
    runner.add_test("test_neg_validate_user_injection", test_neg_validate_user_injection);
}
