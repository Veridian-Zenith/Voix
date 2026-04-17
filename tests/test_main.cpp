#include "test_main.h"
#include <iostream>
#include <print>

void test_isSecurePath();
void test_resolveCommand();

int run_tests([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    test_isSecurePath();
    test_resolveCommand();
    std::println("All tests passed!");
    return 0;
}

int main(int argc, char** argv) {
    return run_tests(argc, argv);
}
