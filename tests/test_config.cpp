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

bool test_config_default_sanctuary() {
    Voix::Config config;
    ASSERT_EQUAL(config.getSanctuary(), std::string("/var/lib/voix"));
    return true;
}

bool test_shipped_config_is_closed_by_default() {
    const std::filesystem::path repo =
        std::filesystem::path(__FILE__).parent_path().parent_path();
    const std::filesystem::path config_path = repo / "config/voix.conf";

    Voix::Config config;
    ASSERT_TRUE(config.load(config_path.string(), false));
    ASSERT_TRUE(config.getRules().empty());
    ASSERT_TRUE(config.get_unconfined_targets().empty());
    ASSERT_EQUAL(config.getSanctuary(), std::string("/var/lib/voix"));
    return true;
}

bool test_config_last_error_is_reported() {
    Voix::Config config;
    ASSERT_TRUE(!config.load("/nonexistent/voix-test.conf", false));
    ASSERT_TRUE(!config.last_error().empty());
    ASSERT_TRUE(config.last_error().find("not found") != std::string::npos);
    return true;
}

bool test_config_rejects_unknown_seccomp_mode() {
    std::filesystem::path config_path =
        std::filesystem::temp_directory_path() / "test_seccomp_mode.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  sanctuary: /var/lib/voix\n"
            << "security:\n  profiles:\n    tight:\n"
            << "      seccomp_mode: blaklist\n";
    }

    Voix::Config config;
    // Rejected at load time so a bad profile can never reach execution.
    ASSERT_TRUE(!config.load(config_path.string(), false));
    // A typo must never silently disable filtering.
    ASSERT_TRUE(config.last_error().find("seccomp_mode") != std::string::npos);
    return true;
}

bool test_config_parses_seccomp_allow() {
    std::filesystem::path config_path =
        std::filesystem::temp_directory_path() / "test_seccomp_allow.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        // validate() requires an existing directory; "/" is always present.
        // This test is about seccomp parsing, not the installed sanctuary.
        out << "core:\n  sanctuary: /\n"
            << "security:\n  profiles:\n    tight:\n"
            << "      seccomp_mode: allowlist\n"
            << "      seccomp_allow: [openat2, mkdir]\n";
    }

    Voix::Config config;
    ASSERT_TRUE(config.load(config_path.string(), false));
    ASSERT_TRUE(config.validate());
    auto profile = config.get_profile("tight");
    ASSERT_EQUAL(profile.seccomp_mode, std::string("allowlist"));
    ASSERT_EQUAL(profile.seccomp_allow.size(), std::size_t{2});
    ASSERT_EQUAL(profile.seccomp_allow[0], std::string("openat2"));
    ASSERT_EQUAL(profile.seccomp_allow[1], std::string("mkdir"));
    return true;
}

bool test_config_rejects_unknown_seccomp_allow_name() {
    std::filesystem::path config_path =
        std::filesystem::temp_directory_path() / "test_seccomp_badname.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  sanctuary: /var/lib/voix\n"
            << "security:\n  profiles:\n    tight:\n"
            << "      seccomp_mode: allowlist\n"
            << "      seccomp_allow: [not_a_real_syscall]\n";
    }

    Voix::Config config;
    ASSERT_TRUE(!config.load(config_path.string(), false));
    ASSERT_TRUE(config.last_error().find("not_a_real_syscall") !=
                std::string::npos);
    return true;
}

bool test_config_rejects_seccomp_allow_without_allowlist() {
    std::filesystem::path config_path =
        std::filesystem::temp_directory_path() / "test_seccomp_mismatch.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  sanctuary: /var/lib/voix\n"
            << "security:\n  profiles:\n    loose:\n"
            << "      seccomp_mode: blacklist\n"
            << "      seccomp_allow: [mkdir]\n";
    }

    Voix::Config config;
    ASSERT_TRUE(!config.load(config_path.string(), false));
    ASSERT_TRUE(config.last_error().find("seccomp_allow") != std::string::npos);
    return true;
}

bool test_config_validate_reports_reason() {
    std::filesystem::path config_path =
        std::filesystem::temp_directory_path() / "test_validate_reason.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  sanctuary: relative/path\n";
    }

    Voix::Config config;
    ASSERT_TRUE(config.load(config_path.string(), false));
    ASSERT_TRUE(!config.validate());
    ASSERT_TRUE(!config.last_error().empty());
    return true;
}

bool test_config_rejects_untrusted_path() {
    std::filesystem::path config_path =
        std::filesystem::temp_directory_path() / "test_untrusted_path.conf";
    ScopedTempFile cleanup(config_path);
    {
        std::ofstream out(config_path);
        out << "core:\n  sanctuary: /tmp\n";
    }

    Voix::Config config;
    // /tmp is group/world writable, so -C-style secure loading must refuse it
    // even if the file itself happens to be owned by the caller.
    ASSERT_TRUE(!config.load(config_path.string(), true));
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
    // Fail closed: no target is unconfined unless the configuration says so.
    ASSERT_TRUE(!config.is_unconfined_target("root"));
    ASSERT_TRUE(!config.is_unconfined_target("alpm"));
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

bool test_config_sanctuary_rejects_empty() {
    auto error = Voix::Config::validate_sanctuary_path("");
    ASSERT_TRUE(error.has_value());
    ASSERT_TRUE(error->find("must not be empty") != std::string::npos);
    return true;
}

bool test_config_sanctuary_rejects_relative() {
    // "." exists as a directory but is not absolute.
    auto error = Voix::Config::validate_sanctuary_path(".");
    ASSERT_TRUE(error.has_value());
    ASSERT_TRUE(error->find("not trusted") != std::string::npos);
    return true;
}

bool test_config_sanctuary_rejects_world_writable() {
    // /tmp exists and is a directory, but it is group/world writable, so an
    // unprivileged user could forge timestamp tickets there.
    auto error = Voix::Config::validate_sanctuary_path("/tmp");
    ASSERT_TRUE(error.has_value());
    ASSERT_TRUE(error->find("not trusted") != std::string::npos);
    return true;
}

bool test_config_sanctuary_rejects_missing_directory() {
    auto error =
        Voix::Config::validate_sanctuary_path("/nonexistent/voix-sanctuary");
    ASSERT_TRUE(error.has_value());
    ASSERT_TRUE(error->find("does not exist") != std::string::npos);
    return true;
}

bool test_config_sanctuary_accepts_trusted_directory() {
    // "/" is root-owned and not group/world writable.
    ASSERT_TRUE(!Voix::Config::validate_sanctuary_path("/").has_value());

    // The shipped sanctuary must pass on systems where it has been installed.
    std::error_code ec;
    if (std::filesystem::is_directory("/var/lib/voix", ec)) {
        ASSERT_TRUE(
            !Voix::Config::validate_sanctuary_path("/var/lib/voix").has_value());
    }
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
    runner.add_test("test_config_default_sanctuary", test_config_default_sanctuary);
    runner.add_test("test_shipped_config_is_closed_by_default",
                    test_shipped_config_is_closed_by_default);
    runner.add_test("test_config_last_error_is_reported",
                    test_config_last_error_is_reported);
    runner.add_test("test_config_validate_reports_reason",
                    test_config_validate_reports_reason);
    runner.add_test("test_config_rejects_unknown_seccomp_mode",
                    test_config_rejects_unknown_seccomp_mode);
    runner.add_test("test_config_parses_seccomp_allow",
                    test_config_parses_seccomp_allow);
    runner.add_test("test_config_rejects_unknown_seccomp_allow_name",
                    test_config_rejects_unknown_seccomp_allow_name);
    runner.add_test("test_config_rejects_seccomp_allow_without_allowlist",
                    test_config_rejects_seccomp_allow_without_allowlist);
    runner.add_test("test_config_rejects_untrusted_path", test_config_rejects_untrusted_path);
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
    runner.add_test("test_config_sanctuary_rejects_empty",
                    test_config_sanctuary_rejects_empty);
    runner.add_test("test_config_sanctuary_rejects_relative",
                    test_config_sanctuary_rejects_relative);
    runner.add_test("test_config_sanctuary_rejects_world_writable",
                    test_config_sanctuary_rejects_world_writable);
    runner.add_test("test_config_sanctuary_rejects_missing_directory",
                    test_config_sanctuary_rejects_missing_directory);
    runner.add_test("test_config_sanctuary_accepts_trusted_directory",
                    test_config_sanctuary_accepts_trusted_directory);
}
