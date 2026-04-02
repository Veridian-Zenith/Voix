# Testing

Voix uses a compile-time testing system.

## Configuration

Tests are enabled by default for Debug builds and disabled for Release builds.

You can explicitly enable or disable the build of tests using the `-DBUILD_TESTING` CMake flag:

- To enable tests: `-DBUILD_TESTING=ON`
- To disable tests: `-DBUILD_TESTING=OFF`

Example:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -G Ninja
cmake --build build
```
