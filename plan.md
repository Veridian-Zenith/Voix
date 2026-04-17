# Plan: Overhaul Voix Build and Testing (Revised)

This plan addresses the user's request to refactor the testing framework and remove the `sudo` requirement for local builds, while avoiding the introduction of complex third-party testing libraries.

## 1. Decouple Build and Installation

The current build process requires `sudo` because it attempts to install files into system directories. We will separate the build and installation steps, so that `sudo` is only required for the final installation.

### Actions

- Ensure the `install()` commands in the root `CMakeLists.txt` are only executed during the `install` step, not the default build.
- Provide clear instructions on how to build and install the project separately:
  - **Build:** `cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug && cmake --build build`
  - **Test:** `cd build && ctest`
  - **Install:** `sudo cmake --install build`

## 2. Enhance the Existing Custom Test Framework

Instead of adding a third-party framework, we will improve the existing custom testing setup to be more robust and better integrated with CTest.

### Actions

- **Improve the test runner:** We will enhance `tests/test_main.cpp` to be a more capable test runner. It will:
  - Register test functions to be run.
  - Execute all registered tests.
  - Report successes and failures for each test.
  - Exit with a non-zero status code if any test fails, which is essential for CTest integration.
- **Create simple assertion macros:** A new header file, `tests/test_assert.h`, will be created. It will contain simple assertion macros like `ASSERT_TRUE(condition)` and `ASSERT_EQUAL(a, b)` to provide clear and consistent test-writing.
- **Re-implement tests:** The existing test files will be deleted and re-implemented using the new assertion macros and test runner.
  - `tests/test_main.cpp`
  - `tests/test_main.h`
  - `tests/test_security.cpp`
  - `tests/test_file_utils.cpp`
- **Proper CTest Integration:** We will ensure the test executable is correctly registered with CTest via `add_test()` in `tests/CMakeLists.txt`, allowing tests to be run automatically with `ctest` or `make test`.

## 3. Conditional Test Compilation

We will maintain the existing logic to only build tests when `CMAKE_BUILD_TYPE` is `Debug`.

## 4. Documentation

We will update the project's documentation to reflect these changes.

### Actions

- Update `README.md` and/or create a `CONTRIBUTING.md` with the new build, test, and install instructions.

This revised plan delivers an automated, integrated, and simple testing solution without adding external dependencies.
