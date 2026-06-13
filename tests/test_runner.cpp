#include "test_assert.hpp"
#include "../include/file_utils.hpp"
#include "../include/security.hpp"
#include "../include/config.hpp"
#include "../include/permission_checker.hpp"
#include "../include/system_identity.hpp"
#include <fstream>
#include <filesystem>
#include <memory>

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

    std::optional<Voix::UserIdentity> getUserByName(const std::string& username) const override {
        for (const auto& u : users) {
            if (u.name == username) return Voix::UserIdentity{u.name, u.uid, u.gid, u.groups, "/home/" + u.name, "/bin/bash"};
        }
        return std::nullopt;
    }
    std::optional<Voix::UserIdentity> getUserByUid(uid_t uid) const override {
        for (const auto& u : users) {
            if (u.uid == uid) return Voix::UserIdentity{u.name, u.uid, u.gid, u.groups, "/home/" + u.name, "/bin/bash"};
        }
        return std::nullopt;
    }
    std::string getCurrentUsername() const override { return current_user; }
    uid_t getCurrentUid() const override { return current_uid; }
    std::vector<gid_t> getCurrentGroups() const override { return current_groups; }
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
    std::string config_path = "test_perm.conf";
    std::ofstream outfile(config_path);
    outfile << "acl:\n  user:\n    1000:\n      - action: permit\n        command: ls\n";
    outfile.close();
    config->load(config_path, false);

    Voix::PermissionChecker checker(security, config);
    auto rule = checker.permit("ls", {}, 0);
    ASSERT_TRUE(rule.has_value());
    ASSERT_EQUAL(static_cast<int>(rule->action), static_cast<int>(Voix::Rule::Action::PERMIT));

    std::filesystem::remove(config_path);
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
    
    std::string config_path = "test_perm_denied.conf";
    std::ofstream outfile(config_path);
    outfile << "acl:\n  user:\n    alice:\n      - action: permit\n        command: ls\n";
    outfile.close();
    config->load(config_path, false);

    Voix::PermissionChecker checker(security, config);
    auto rule = checker.permit("ls", {}, 0);
    ASSERT_TRUE(!rule.has_value());

    std::filesystem::remove(config_path);
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

int main() {
    TestRunner runner;
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
    return runner.run();
}
