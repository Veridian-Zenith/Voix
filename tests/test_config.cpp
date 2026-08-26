/**
 * @file test_config.cpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

/**
 * @file test_config.cpp
 * @brief Config loading/validation unit tests.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

#include "test_modules.hpp"

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
    // Exact entries must not leak into the regex list.
    ASSERT_EQUAL(static_cast<int>(config.get_regex_blocklist().size()), 0);
    return true;
}

bool test_config_blocklist_regex_entries() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_blocklist_regex.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  paths: [/bin]\n  sanctuary: /tmp\n"
            << "security:\n  blocklist:\n"
            << "    - /bin/sh\n"
            << "    - regex:^cat /etc/(shadow|sudoers)\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));

    const auto& regexes = config.get_regex_blocklist();
    ASSERT_EQUAL(static_cast<int>(regexes.size()), 1);
    ASSERT_EQUAL(regexes[0].first, std::string("^cat /etc/(shadow|sudoers)"));

    // Exact entry stays exact
    ASSERT_EQUAL(static_cast<int>(config.get_blocklist().size()), 1);

    // The compiled regex actually matches the intended command line
    ASSERT_TRUE(std::regex_search("cat /etc/shadow extra", regexes[0].second));
    ASSERT_TRUE(!std::regex_search("cat /etc/passwd", regexes[0].second));
    return true;
}

bool test_config_blocklist_invalid_regex_rejected() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_blocklist_badregex.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "security:\n  blocklist:\n    - \"regex:[unclosed\"\n";
    }
    // Malformed admin regex must fail the load, not silently pass through.
    ASSERT_TRUE(!config.load(config_path.string(), false));
    return true;
}

bool test_config_envlist_valid() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_envlist.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "acl:\n  user:\n    root:\n"
            << "      - action: permit\n        env: [MYVAR=hello, _PRIVATE=1]\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));
    const auto& rules = config.getRules();
    ASSERT_EQUAL(static_cast<int>(rules.size()), 1);
    ASSERT_EQUAL(static_cast<int>(rules[0].envlist.size()), 2);
    ASSERT_EQUAL(rules[0].envlist[0], std::string("MYVAR=hello"));
    return true;
}

bool test_config_envlist_invalid_rejected() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_envlist_bad.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        // No '=' separator
        out << "acl:\n  user:\n    root:\n          - action: permit\n            env: [BROKEN]\n";
    }
    ASSERT_TRUE(!config.load(config_path.string(), false));
    return true;
}

bool test_config_envlist_invalid_key_rejected() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_envlist_badkey.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        // Key with a dash is not a valid environment variable name
        out << "acl:\n  user:\n    root:\n          - action: permit\n            env: [BAD-KEY=x]\n";
    }
    ASSERT_TRUE(!config.load(config_path.string(), false));
    return true;
}

bool test_config_rule_options_parsed() {
    Voix::Config config;
    std::filesystem::path config_path = std::filesystem::temp_directory_path() / "test_rule_opts.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "acl:\n  user:\n    root:\n"
            << "      - action: permit\n"
            << "        options: [trust, keepenv, persist, nolog]\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));
    const auto& rules = config.getRules();
    ASSERT_EQUAL(static_cast<int>(rules.size()), 1);
    ASSERT_TRUE(rules[0].options & Voix::Rule::NOPASS);
    ASSERT_TRUE(rules[0].options & Voix::Rule::KEEPENV);
    ASSERT_TRUE(rules[0].options & Voix::Rule::PERSIST);
    ASSERT_TRUE(rules[0].options & Voix::Rule::NOLOG);
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

bool test_config_unconfined_targets() {
    Voix::Config config;
    ASSERT_TRUE(config.is_unconfined_target("root"));
    ASSERT_TRUE(config.is_unconfined_target("alpm"));
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

bool test_config_security_profile_rule_survives_parse() {
    // Regression: rules referencing security.profiles must not be swallowed
    // by any template-expansion path — they resolve at execution time.
    Voix::Config config;
    std::filesystem::path config_path =
        std::filesystem::temp_directory_path() / "test_profile_rule.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "acl:\n  user:\n    root:\n"
            << "      - action: permit\n        command: /usr/bin/pacman\n"
            << "        profile: privileged\n";
    }
    ASSERT_TRUE(config.load(config_path.string(), false));
    const auto& rules = config.getRules();
    ASSERT_EQUAL(static_cast<int>(rules.size()), 1);
    ASSERT_EQUAL(rules[0].profile, std::string("privileged"));
    return true;
}

void register_config_tests(TestRunner& runner) {
    runner.add_test("test_config_load_valid", test_config_load_valid);
    runner.add_test("test_config_load_invalid_yaml", test_config_load_invalid_yaml);
    runner.add_test("test_config_load_nonexistent", test_config_load_nonexistent);
    runner.add_test("test_config_get_rules_empty", test_config_get_rules_empty);
    runner.add_test("test_config_validate_after_load", test_config_validate_after_load);
    runner.add_test("test_config_blocklist", test_config_blocklist);
    runner.add_test("test_config_blocklist_regex_entries", test_config_blocklist_regex_entries);
    runner.add_test("test_config_blocklist_invalid_regex_rejected", test_config_blocklist_invalid_regex_rejected);
    runner.add_test("test_config_envlist_valid", test_config_envlist_valid);
    runner.add_test("test_config_envlist_invalid_rejected", test_config_envlist_invalid_rejected);
    runner.add_test("test_config_envlist_invalid_key_rejected", test_config_envlist_invalid_key_rejected);
    runner.add_test("test_config_rule_options_parsed", test_config_rule_options_parsed);
    runner.add_test("test_config_security_profile_rule_survives_parse",
                    test_config_security_profile_rule_survives_parse);
    runner.add_test("test_config_seccomp_default_enabled", test_config_seccomp_default_enabled);
    runner.add_test("test_config_unconfined_targets", test_config_unconfined_targets);
    runner.add_test("test_config_validate_valid_config", test_config_validate_valid_config);
    runner.add_test("test_config_validate_relative_path", test_config_validate_relative_path);
    runner.add_test("test_config_validate_empty_sanctuary", test_config_validate_empty_sanctuary);
}
