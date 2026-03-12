#include <gtest/gtest.h>
#include "security.h"

using namespace Voix;

TEST(SecurityTest, ValidateUserValid) {
    Security security;
    EXPECT_TRUE(security.validateUser("root"));
}

TEST(SecurityTest, ValidateUserInvalid) {
    Security security;
    EXPECT_FALSE(security.validateUser("invalid_user_name_with_lots_of_chars_1234567890"));
    EXPECT_FALSE(security.validateUser("invalid!user"));
}

TEST(SecurityTest, IsSafePath) {
    Security security;
    EXPECT_TRUE(security.isSafePath("/var/log/messages"));
    EXPECT_FALSE(security.isSafePath("/etc/shadow"));
    EXPECT_FALSE(security.isSafePath("/home/user/../../etc/passwd"));
}

TEST(SecurityTest, IsDangerousCommand) {
    Security security;
    EXPECT_TRUE(security.isDangerousCommand("sudo"));
    EXPECT_TRUE(security.isDangerousCommand("su"));
    EXPECT_FALSE(security.isDangerousCommand("ls"));
}