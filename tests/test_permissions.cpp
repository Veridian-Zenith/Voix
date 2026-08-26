/**
 * @file test_permissions.cpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

/**
 * @file test_permissions.cpp
 * @brief PermissionChecker unit tests.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

#include "test_modules.hpp"

bool test_permission_checker_permit_allowed() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"alice", 1000, 1000, {1000, 4}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000, 4};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_perm.conf";
    ScopedTempFile cleanup_guard(config_path);
    {
        std::ofstream outfile(config_path);
        outfile << "acl:\n  user:\n    1000:\n      - action: permit\n        command: ls\n";
    }
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
    {
        std::ofstream outfile(config_path);
        outfile << "acl:\n  user:\n    alice:\n      - action: permit\n        command: ls\n";
    }
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);
    auto rule = checker.permit("ls", {}, 0);
    ASSERT_TRUE(!rule.has_value());

    return true;
}

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
    auto rule_ls = checker.permit("ls", {}, 0);
    ASSERT_TRUE(rule_ls.has_value());
    auto rule_cat = checker.permit("cat", {}, 0);
    ASSERT_TRUE(!rule_cat.has_value());
    return true;
}

bool test_permission_checker_first_match_deny_wins() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"alice", 1000, 1000, {1000}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_perm_firstmatch.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        // Deny first; a later identical permit must not override it.
        out << "acl:\n  user:\n    1000:\n"
            << "      - action: deny\n        command: rm\n"
            << "      - action: permit\n        command: rm\n";
    }
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);
    ASSERT_TRUE(!checker.permit("rm", {}, 0).has_value());
    return true;
}

bool test_permission_checker_pattern_args() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"alice", 1000, 1000, {1000}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_perm_pattern.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "acl:\n  user:\n    1000:\n"
            << "      - action: permit\n        command: systemctl\n        args: [restart, nginx*]\n";
    }
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);
    // Wrong arg count never matches
    ASSERT_TRUE(!checker.permit("systemctl", {"restart"}, 0).has_value());
    // Wildcard match
    ASSERT_TRUE(checker.permit("systemctl", {"restart", "nginx.service"}, 0).has_value());
    // Wildcard mismatch
    ASSERT_TRUE(!checker.permit("systemctl", {"restart", "sshd.socket"}, 0).has_value());
    return true;
}

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
    ASSERT_EQUAL(static_cast<int>(rules.size()), 2);
    ASSERT_EQUAL(rules[0].cmd, std::string("ls"));
    ASSERT_EQUAL(rules[1].cmd, std::string("cat"));
    return true;
}

bool test_permission_checker_list_respects_first_match_deny() {
    auto mock_id = std::make_shared<MockIdentity>();
    mock_id->users = {{"alice", 1000, 1000, {1000}}};
    mock_id->current_user = "alice";
    mock_id->current_uid = 1000;
    mock_id->current_groups = {1000};

    auto security = std::make_shared<Voix::Security>(mock_id);
    auto config = std::make_shared<Voix::Config>();

    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_list_deny.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        // deny rm comes first — a later permit for the same scope is dead
        // policy and must not be listed by `voix -l`.
        out << "acl:\n  user:\n    1000:\n"
            << "      - action: deny\n        command: rm\n"
            << "      - action: permit\n        command: rm\n"
            << "      - action: permit\n        command: cat\n";
    }
    config->load(config_path.string(), false);

    Voix::PermissionChecker checker(security, config);
    auto rules = checker.list_permitted_rules();
    ASSERT_EQUAL(static_cast<int>(rules.size()), 1);
    ASSERT_EQUAL(rules[0].cmd, std::string("cat"));
    return true;
}

void register_permission_tests(TestRunner& runner) {
    runner.add_test("test_permission_checker_permit_allowed", test_permission_checker_permit_allowed);
    runner.add_test("test_permission_checker_permit_denied", test_permission_checker_permit_denied);
    runner.add_test("test_permission_checker_group_rule", test_permission_checker_group_rule);
    runner.add_test("test_permission_checker_deny_rule", test_permission_checker_deny_rule);
    runner.add_test("test_permission_checker_command_specific", test_permission_checker_command_specific);
    runner.add_test("test_permission_checker_first_match_deny_wins", test_permission_checker_first_match_deny_wins);
    runner.add_test("test_permission_checker_pattern_args", test_permission_checker_pattern_args);
    runner.add_test("test_permission_checker_list_permitted_rules", test_permission_checker_list_permitted_rules);
    runner.add_test("test_permission_checker_list_respects_first_match_deny",
                    test_permission_checker_list_respects_first_match_deny);
}
