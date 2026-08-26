/**
 * @file test_command.cpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

/**
 * @file test_command.cpp
 * @brief Command profile-resolution tests.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

#include "test_modules.hpp"

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

void register_command_tests(TestRunner& runner) {
    runner.add_test("test_command_resolve_profile_matrix", test_command_resolve_profile_matrix);
}
