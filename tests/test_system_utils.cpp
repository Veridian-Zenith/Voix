/**
 * @file test_system_utils.cpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

/**
 * @file test_system_utils.cpp
 * @brief SystemUtils unit tests.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

#include "test_modules.hpp"

bool test_get_uid_by_name_root() {
    auto uid = Voix::SystemUtils::getUidByName("root");
    ASSERT_TRUE(uid.has_value());
    ASSERT_EQUAL(uid.value(), static_cast<uid_t>(0));
    return true;
}

bool test_get_uid_by_name_nonexistent() {
    auto uid = Voix::SystemUtils::getUidByName("nonexistent_user_xyz_999");
    ASSERT_TRUE(!uid.has_value());
    return true;
}

bool test_get_gid_by_name_root() {
    auto gid = Voix::SystemUtils::getGidByName("root");
    ASSERT_TRUE(gid.has_value());
    ASSERT_EQUAL(gid.value(), static_cast<gid_t>(0));
    return true;
}

bool test_get_gid_by_name_nonexistent() {
    auto gid = Voix::SystemUtils::getGidByName("nonexistent_group_xyz_999");
    ASSERT_TRUE(!gid.has_value());
    return true;
}

bool test_set_environment() {
    Voix::SystemUtils sys_utils;
    std::vector<std::string> env_vars = {"VOIX_TEST_VAR=hello_world"};
    sys_utils.setEnvironment(env_vars);

    const char* val = std::getenv("VOIX_TEST_VAR");
    ASSERT_TRUE(val != nullptr);
    ASSERT_EQUAL(std::string(val), std::string("hello_world"));

    unsetenv("VOIX_TEST_VAR");
    return true;
}

bool test_set_environment_multiple() {
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

bool test_set_environment_overwrite() {
    Voix::SystemUtils sys_utils;
    setenv("VOIX_TEST_OVERWRITE", "original", 1);

    std::vector<std::string> env_vars = {"VOIX_TEST_OVERWRITE=updated"};
    sys_utils.setEnvironment(env_vars);

    ASSERT_EQUAL(std::string(std::getenv("VOIX_TEST_OVERWRITE")), std::string("updated"));

    unsetenv("VOIX_TEST_OVERWRITE");
    return true;
}

bool test_set_environment_empty_value() {
    Voix::SystemUtils sys_utils;
    std::vector<std::string> env_vars = {"VOIX_TEST_EMPTY="};
    sys_utils.setEnvironment(env_vars);

    const char* val = std::getenv("VOIX_TEST_EMPTY");
    ASSERT_TRUE(val != nullptr);
    ASSERT_EQUAL(std::string(val), std::string(""));

    unsetenv("VOIX_TEST_EMPTY");
    return true;
}

bool test_set_environment_no_equals() {
    Voix::SystemUtils sys_utils;
    // Strings without '=' should be silently ignored
    std::vector<std::string> env_vars = {"NOEQUALSIGN"};
    sys_utils.setEnvironment(env_vars);
    const char* val = std::getenv("NOEQUALSIGN");
    ASSERT_TRUE(val == nullptr);
    return true;
}

bool test_lookup_passwd_roundtrip() {
    auto by_name = Voix::lookup_passwd_by_name("root");
    ASSERT_TRUE(by_name.has_value());
    ASSERT_EQUAL(by_name->name, std::string("root"));
    ASSERT_EQUAL(by_name->uid, static_cast<uid_t>(0));

    auto by_uid = Voix::lookup_passwd_by_uid(0);
    ASSERT_TRUE(by_uid.has_value());
    ASSERT_EQUAL(by_uid->uid, static_cast<uid_t>(0));

    ASSERT_TRUE(!Voix::lookup_passwd_by_name("no_such_user_xyz_42").has_value());
    return true;
}

void register_system_utils_tests(TestRunner& runner) {
    runner.add_test("test_get_uid_by_name_root", test_get_uid_by_name_root);
    runner.add_test("test_get_uid_by_name_nonexistent", test_get_uid_by_name_nonexistent);
    runner.add_test("test_get_gid_by_name_root", test_get_gid_by_name_root);
    runner.add_test("test_get_gid_by_name_nonexistent", test_get_gid_by_name_nonexistent);
    runner.add_test("test_set_environment", test_set_environment);
    runner.add_test("test_set_environment_multiple", test_set_environment_multiple);
    runner.add_test("test_set_environment_overwrite", test_set_environment_overwrite);
    runner.add_test("test_set_environment_empty_value", test_set_environment_empty_value);
    runner.add_test("test_set_environment_no_equals", test_set_environment_no_equals);
    runner.add_test("test_lookup_passwd_roundtrip", test_lookup_passwd_roundtrip);
}
