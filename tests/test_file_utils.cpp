#include <gtest/gtest.h>
#include "file_utils.h"
#include <string_view>
#include <string>

using namespace Voix;

TEST(FileUtilsTest, FileExists) {
    FileUtils utils;
    EXPECT_TRUE(utils.fileExists("/etc/passwd"));
    EXPECT_FALSE(utils.fileExists("/path/to/nonexistent/file"));
}