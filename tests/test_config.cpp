#include <gtest/gtest.h>
#include "config.h"

using namespace Voix;

TEST(ConfigTest, LoadMissingFile) {
    Config config;
    EXPECT_FALSE(config.load("/path/to/nonexistent/file.conf"));
}