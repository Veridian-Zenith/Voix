# Contributing to Voix

We welcome all who wish to help forge the future of Voix. To maintain the artifact's purity and security, we ask that you follow these sacred rituals.

## The Architect's Code

1. **Modernity**: All code must be written in **C++26**.
2. **The Toolchain**: We exclusively use the **LLVM/Clang** toolchain. Ensure your environment matches (Clang 21+).
3. **Purity**: Before submitting your changes, run `clang-tidy` to cleanse the code of any lingering chaos.
4. **Security**: Voix is a security-critical tool. Be thorough, be careful, and always consider the principle of least privilege.

## Development Rituals

### 1. Preparing the Forge

```bash
cmake -B build -G Ninja -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang -DVOIX_HARDEN=ON
```

### 2. Cleansing the Code (Tidy)

We encourage contributors to run `clang-tidy` and address any warnings:

```bash
# Example command (adjust paths as needed)
clang-tidy src/*.cpp include/*.h -- -Iinclude -std=c++26
```

### 3. Testing the Artifact

Ensure all tests pass before proposing your changes:

```bash
cmake --build build --target test
```

## Proposing Changes

1. **Open an Issue**: Discuss your proposed changes in a new Issue or Discussion first.
2. **Create a Branch**: Use a descriptive name for your branch.
3. **Submit a Pull Request**: Provide a clear description of your changes and why they are necessary.

## Community

Join our [GitHub Discussions](https://github.com/Veridian-Zenith/Voix/discussions) to share ideas, ask questions, and connect with other architects.
