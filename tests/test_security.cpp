/**
 * @file test_security.cpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

/**
 * @file test_security.cpp
 * @brief Security (validateUser, catastrophic commands, ticket store) tests.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

#include "test_modules.hpp"
#include <unistd.h>
#include <sys/stat.h>

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

bool test_security_catastrophic_command() {
    Voix::Security security;
    Voix::Config config;
    std::vector<std::string> args = {"-rf", "/"};
    ASSERT_TRUE(security.isCatastrophicCommand("rm", args, config));

    std::vector<std::string> safe_args = {"-l"};
    ASSERT_TRUE(!security.isCatastrophicCommand("ls", safe_args, config));
    return true;
}

bool test_security_catastrophic_rm_variants() {
    Voix::Security security;
    Voix::Config config;

    // Separate flags
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-r", "-f", "/"}, config));
    // Combined short flags in either order
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-fr", "/"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-Rf", "/"}, config));
    // Root globs
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-rf", "/*"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-rf", "/**"}, config));
    // Double slash
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-rf", "//"}, config));
    // GNU long options
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"--recursive", "--force", "/"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"--force", "--recursive=/", "/"}, config));

    // Absolute paths to rm are also caught
    ASSERT_TRUE(security.isCatastrophicCommand("/bin/rm", {"-rf", "/"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/usr/bin/rm", {"-rf", "/"}, config));

    // Safe rm commands should not be catastrophic
    ASSERT_TRUE(!security.isCatastrophicCommand("rm", {"-rf", "/tmp/safe_dir"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("rm", {"file.txt"}, config));
    // Recursive without force is not blocked
    ASSERT_TRUE(!security.isCatastrophicCommand("rm", {"-r", "/tmp/x"}, config));
    return true;
}

bool test_security_catastrophic_rm_cwd_relative() {
    // From a temporary cwd, "." must not be flagged...
    ScopedTempFile cwd_guard("/tmp/voix_test_cwd_rm", true);
    std::filesystem::create_directories("/tmp/voix_test_cwd_rm");
    std::filesystem::path old = std::filesystem::current_path();
    std::filesystem::current_path("/tmp/voix_test_cwd_rm");

    Voix::Security security;
    Voix::Config config;
    ASSERT_TRUE(!security.isCatastrophicCommand("rm", {"-rf", "."}, config));

    // ...but from the filesystem root it is catastrophic.
    std::filesystem::current_path("/");
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-rf", "."}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-rf", ".."}, config));
    // Traversal that lands at root regardless of cwd.
    ASSERT_TRUE(security.isCatastrophicCommand("rm", {"-rf", "/.."}, config));

    std::filesystem::current_path(old);
    return true;
}

bool test_security_catastrophic_blocklist_exact() {
    auto identity = std::make_shared<MockIdentity>();
    identity->users = {{"root", 0, 0, {0}}};
    identity->current_user = "root";

    Voix::Security security(identity);
    Voix::Config config;

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_cat_blocklist.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin]\n  sanctuary: /tmp\n"
            << "security:\n  blocklist:\n    - /bin/sh\n"
            << "    - regex:^cat /etc/(shadow|sudoers)\n";
    }
    config.load(config_path.string(), false);

    // Exact scalar entry matches the command alone
    ASSERT_TRUE(security.isCatastrophicCommand("/bin/sh", {}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("/bin/ls", {}, config));

    // regex: entries match the canonicalized full command line
    ASSERT_TRUE(security.isCatastrophicCommand("cat", {"/etc/shadow"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("cat", {"/etc/sudoers"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("cat", {"/etc/passwd"}, config));
    return true;
}

bool test_security_catastrophic_dd() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(security.isCatastrophicCommand("dd", {"if=/dev/zero", "of=/dev/sda", "bs=1M"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("dd", {"if=/dev/zero", "of=/dev/nvme0n1"}, config));
    // VirtIO, MMC, device-mapper and /dev/disk aliases are covered too
    ASSERT_TRUE(security.isCatastrophicCommand("dd", {"of=/dev/vda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("dd", {"of=/dev/mmcblk0"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("dd", {"of=/dev/mapper/cryptroot"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("dd", {"of=/dev/disk/by-id/root"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/bin/dd", {"if=/dev/zero", "of=/dev/sdb"}, config));

    ASSERT_TRUE(!security.isCatastrophicCommand("dd", {"if=/dev/zero", "of=disk.img"}, config));
    ASSERT_TRUE(!security.isCatastrophicCommand("dd", {"--help"}, config));
    return true;
}

bool test_security_catastrophic_mkfs_family() {
    Voix::Security security;
    Voix::Config config;

    ASSERT_TRUE(security.isCatastrophicCommand("mkfs.ext4", {"/dev/sda1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("mkfs.btrfs", {"/dev/sdb1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("mkfs.fat", {"/dev/sdc1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("mkfs", {"-t", "ext4", "/dev/sdc1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/sbin/mkfs.xfs", {"/dev/sdd1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("mkswap", {"/dev/sde1"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/usr/sbin/mkswap", {"/dev/sdf1"}, config));
    return true;
}

bool test_security_catastrophic_partition_tools() {
    Voix::Security security;
    Voix::Config config;

    // Basename matching covers any path prefix, including tools not present
    // in the historical hardcoded list.
    ASSERT_TRUE(security.isCatastrophicCommand("fdisk", {"/dev/sda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/sbin/fdisk", {"/dev/sda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("sfdisk", {"/dev/sda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("/usr/bin/cfdisk", {"/dev/sda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("parted", {"/dev/sda"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("wipe", {"-a", "/dev/sdb"}, config));
    ASSERT_TRUE(security.isCatastrophicCommand("wipefs", {"/dev/sdc"}, config));
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

bool test_ticket_store_roundtrip() {
    ScopedTempFile guard("/tmp/voix_test_tickets", true);
    std::filesystem::create_directories("/tmp/voix_test_tickets");

    Voix::TicketStore tickets("/tmp/voix_test_tickets");
    const uid_t uid = 4242;

    ASSERT_TRUE(!tickets.valid(uid));
    ASSERT_TRUE(tickets.record(uid));

    // Fresh ticket is valid; expired one is not.
    ASSERT_TRUE(tickets.valid(uid, std::chrono::minutes(15)));
    ASSERT_TRUE(tickets.valid(uid, std::chrono::minutes(0)));

    tickets.clear(uid);
    ASSERT_TRUE(!tickets.valid(uid));

    // Clearing twice is harmless.
    tickets.clear(uid);
    return true;
}

bool test_ticket_store_garbage_rejected() {
    ScopedTempFile guard("/tmp/voix_test_tickets2", true);
    auto dir = std::filesystem::temp_directory_path() / "voix_test_tickets2";
    std::filesystem::create_directories(dir);

    Voix::TicketStore tickets(dir.string());
    const uid_t uid = static_cast<uid_t>(geteuid());  // writable by us

    Voix::FileUtils fu;
    ASSERT_TRUE(fu.ensure_private_directory(dir / "timestamp"));
    auto f = dir / "timestamp" / std::to_string(uid);
    {
        std::ofstream out(f);
        out << "not-a-number";
    }
    ASSERT_TRUE(!tickets.valid(uid));

    {
        std::ofstream out(f);
        out << "99999999999999999999";  // Far future — tampering rejected
    }
    ASSERT_TRUE(!tickets.valid(uid));

    tickets.clear(uid);
    return true;
}

void register_security_tests(TestRunner& runner) {
    runner.add_test("test_security_validate_user_valid", test_security_validate_user_valid);
    runner.add_test("test_security_validate_user_invalid", test_security_validate_user_invalid);
    runner.add_test("test_security_validate_user_too_long", test_security_validate_user_too_long);
    runner.add_test("test_security_validate_user_bad_chars", test_security_validate_user_bad_chars);
    runner.add_test("test_security_validate_user_underscore_hyphen", test_security_validate_user_underscore_hyphen);
    runner.add_test("test_security_validate_user_empty", test_security_validate_user_empty);
    runner.add_test("test_security_get_current_user", test_security_get_current_user);
    runner.add_test("test_security_catastrophic_command", test_security_catastrophic_command);
    runner.add_test("test_security_catastrophic_rm_variants", test_security_catastrophic_rm_variants);
    runner.add_test("test_security_catastrophic_rm_cwd_relative", test_security_catastrophic_rm_cwd_relative);
    runner.add_test("test_security_catastrophic_blocklist_exact", test_security_catastrophic_blocklist_exact);
    runner.add_test("test_security_catastrophic_dd", test_security_catastrophic_dd);
    runner.add_test("test_security_catastrophic_mkfs_family", test_security_catastrophic_mkfs_family);
    runner.add_test("test_security_catastrophic_partition_tools", test_security_catastrophic_partition_tools);
    runner.add_test("test_security_catastrophic_safe_commands", test_security_catastrophic_safe_commands);
    runner.add_test("test_ticket_store_roundtrip", test_ticket_store_roundtrip);
    runner.add_test("test_ticket_store_garbage_rejected", test_ticket_store_garbage_rejected);
}
