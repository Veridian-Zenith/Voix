#include "test_assert.h"
#include "../include/file_utils.h"
#include "../include/security.h"
#include "../include/config.h"

bool test_file_exists() {
    Voix::FileUtils file_utils;
    ASSERT_TRUE(file_utils.fileExists("CMakeLists.txt"));
    ASSERT_TRUE(!file_utils.fileExists("non_existent_file_xyz"));
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
    runner.add_test("test_file_exists", test_file_exists);
    runner.add_test("test_security_safe_path", test_security_safe_path);
    runner.add_test("test_security_catastrophic_command", test_security_catastrophic_command);
    return runner.run();
}
