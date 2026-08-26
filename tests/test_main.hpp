/**
 * @file test_main.hpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#pragma once

/**
 * @file test_main.hpp
 * @brief Test harness entry point, linked into the voix binary for
 *        BUILD_TESTING builds (`voix --run-tests`) and into the standalone
 *        test_runner executable.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

namespace VoixTest {

/**
 * @brief Runs the full unit-test suite.
 * @return 0 if all tests pass, non-zero otherwise.
 */
int run_tests(int argc, char* argv[]);

} // namespace VoixTest
