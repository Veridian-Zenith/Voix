#include "test_assert.h"
#include "../include/file_utils.h"

bool test_file_exists() {
    Voix::FileUtils file_utils;
    // Should exist (this file, for example)
    ASSERT_TRUE(file_utils.fileExists("CMakeLists.txt"));
    // Should not exist
    ASSERT_TRUE(!file_utils.fileExists("non_existent_file_xyz"));
    return true;
}

int main() {
    TestRunner runner;
    runner.add_test("test_file_exists", test_file_exists);
    return runner.run();
}
