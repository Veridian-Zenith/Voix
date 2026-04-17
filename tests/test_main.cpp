#include "test_main.h"
#include <iostream>

void test_isSecurePath();

int run_tests([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    test_isSecurePath();
    std::println("All tests passed!");
    return 0;
}
