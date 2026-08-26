/**
 * @file test_logger.cpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

/**
 * @file test_logger.cpp
 * @brief Logger unit tests.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

#include "test_modules.hpp"

bool test_logger_timestamp_format() {
    Voix::Logger logger;
    std::string ts = logger.getTimestamp();
    ASSERT_TRUE(ts.length() >= 19);
    ASSERT_EQUAL(ts[4], '-');
    ASSERT_EQUAL(ts[7], '-');
    ASSERT_EQUAL(ts[10], ' ');
    ASSERT_EQUAL(ts[13], ':');
    ASSERT_EQUAL(ts[16], ':');
    return true;
}

bool test_logger_timestamp_current_year() {
    Voix::Logger logger;
    std::string ts = logger.getTimestamp();
    auto now = std::chrono::system_clock::now();
    auto today = std::chrono::year_month_day{std::chrono::floor<std::chrono::days>(now)};
    int current_year = static_cast<int>(today.year());
    int year = std::stoi(ts.substr(0, 4));
    ASSERT_TRUE(year >= current_year);
    return true;
}

bool test_logger_log_does_not_crash() {
    Voix::Logger logger;
    logger.log("INFO", "test message");
    logger.log("ERROR", "error message");
    logger.log("WARN", "warning message");
    return true;
}

bool test_logger_log_empty_message() {
    Voix::Logger logger;
    logger.log("", "");
    logger.log("INFO", "");
    logger.log("", "some message");
    return true;
}

bool test_logger_sanitize_newlines() {
    // Newlines in untrusted strings must never produce extra log lines.
    ASSERT_EQUAL(Voix::Logger::sanitize_message("evil\nFAKE LOG LINE"),
                 std::string("evil\\nFAKE LOG LINE"));
    ASSERT_EQUAL(Voix::Logger::sanitize_message("a\r\ncarriage"),
                 std::string("a\\r\\ncarriage"));
    ASSERT_EQUAL(Voix::Logger::sanitize_message("tab\tkept-escaped"),
                 std::string("tab\\tkept-escaped"));
    ASSERT_EQUAL(Voix::Logger::sanitize_message("clean string"),
                 std::string("clean string"));
    ASSERT_TRUE(Voix::Logger::sanitize_message("").empty());
    return true;
}

bool test_logger_sanitize_control_chars() {
    ASSERT_EQUAL(Voix::Logger::sanitize_message(std::string("null\0byte", 9)),
                 std::string("null\\x00byte"));
    ASSERT_EQUAL(Voix::Logger::sanitize_message("\x01\x1f\x7f"),
                 std::string("\\x01\\x1f\\x7f"));
    return true;
}

void register_logger_tests(TestRunner& runner) {
    runner.add_test("test_logger_timestamp_format", test_logger_timestamp_format);
    runner.add_test("test_logger_timestamp_current_year", test_logger_timestamp_current_year);
    runner.add_test("test_logger_log_does_not_crash", test_logger_log_does_not_crash);
    runner.add_test("test_logger_log_empty_message", test_logger_log_empty_message);
    runner.add_test("test_logger_sanitize_newlines", test_logger_sanitize_newlines);
    runner.add_test("test_logger_sanitize_control_chars", test_logger_sanitize_control_chars);
}
