# Testing

Voix features automated test execution directly integrated into the build process.

## How it Works

When `BUILD_TESTING` is enabled (default for Debug builds), a custom target `run_tests` is created. The main `voix` target is configured to depend on `run_tests`. 

This means **tests are run automatically during the build process**. If any test fails, the build itself is marked as failed, preventing broken binaries from being accidentally compiled or packaged.

## Configuration

Tests are enabled by default for Debug builds and disabled for Release builds.

You can explicitly enable or disable the build of tests using the `-DBUILD_TESTING` CMake flag:

- To enable tests: `-DBUILD_TESTING=ON`
- To disable tests: `-DBUILD_TESTING=OFF`

### Building and Running Tests (Debug Mode)

To configure and compile a Debug build (which automatically runs tests):

```bash
cmake -B build-debug -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug && cmake --build build-debug
```

### Force-enabling Tests (Release Mode)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -G Ninja
cmake --build build
```
