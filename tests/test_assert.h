#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <functional>

#define ASSERT_TRUE(condition) \
    do { \
        if (!(condition)) { \
            std::cerr << "Assertion failed: " << #condition << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
            return false; \
        } \
    } while (0)

#define ASSERT_EQUAL(a, b) \
    do { \
        if ((a) != (b)) { \
            std::cerr << "Assertion failed: " << #a << " == " << #b << " (got: " << (a) << ", expected: " << (b) << ") at " << __FILE__ << ":" << __LINE__ << std::endl; \
            return false; \
        } \
    } while (0)

struct TestCase {
    std::string name;
    std::function<bool()> test_func;
};

class TestRunner {
public:
    void add_test(const std::string& name, std::function<bool()> func) {
        tests.push_back({name, func});
    }

    int run() {
        int passed = 0;
        int failed = 0;
        for (const auto& test : tests) {
            std::cout << "[RUNNING] " << test.name << "..." << std::endl;
            if (test.test_func()) {
                std::cout << "[PASSED] " << test.name << std::endl;
                passed++;
            } else {
                std::cout << "[FAILED] " << test.name << std::endl;
                failed++;
            }
        }
        std::cout << "Tests passed: " << passed << ", Failed: " << failed << std::endl;
        return failed == 0 ? 0 : 1;
    }

private:
    std::vector<TestCase> tests;
};
