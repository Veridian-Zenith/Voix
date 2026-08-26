/**
 * @file run_tests.cpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

/**
 * @file run_tests.cpp
 * @brief Test suite assembly: registers all modules and runs them. Used by
 *        both the standalone test_runner binary and `voix --run-tests`.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

#include "test_modules.hpp"
#include "test_main.hpp"

namespace VoixTest {

int run_tests(int /*argc*/, char* /*argv*/[]) {
    Voix::Logger::suppress_stderr = true;
    TestRunner runner;

    register_permission_tests(runner);
    register_config_tests(runner);
    register_security_tests(runner);
    register_command_tests(runner);
    register_file_utils_tests(runner);
    register_logger_tests(runner);
    register_system_utils_tests(runner);
    register_negative_security_tests(runner);

    return runner.run();
}

} // namespace VoixTest
