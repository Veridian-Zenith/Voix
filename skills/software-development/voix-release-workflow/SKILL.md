---
name: voix-release-workflow
description: "Build, test, release, and verify Voix artifacts (C++26, clang-only, setuid, black/allow seccomp, multi-arch)."
version: 0.1.0
author: "Dae Euhwa (daedaevibin@ik.me), Hermes Agent"
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [voix, privilege-escalation, c++26, clang-only, seccomp, multi-arch, aarch64, packaging]
    related_skills: [hermes-agent]
---

# Voix Release Workflow

Build, test, release verification, packaging, and multi-arch workflow for the Voix Privilege Policy Enforcement Runtime.

## When to Use

- Building `build/` (release) and `build-debug/` (tests) after code changes.
- Running `clang-tidy` / `clang-format` before pushing.
- Creating/releasing `v*` tags with build artifacts.
- Adding multi-arch artifacts (`aarch64`) or packaging updates (AUR, `.github/workflows/release.yml`).
- Updating version references across `CMakeLists.txt`, `src/main.cpp`, `docs/voix.1`, `PKGBUILD` files together.

Don't use for: debugging individual security rules (see `security.cpp` directly) or user-local profile customization.

## Prerequisites

- Clang 22+ with LLD (`clang++`, `clang`, `lld`)
- CMake 3.30+, Ninja
- `yaml-cpp`, `pam`, `libcap`, `libseccomp` (dev headers)
- `ccache` (optional, used by CMake)
- `.clang-tidy` and `.clangd` present at repo root (verified present)

## How to Run

### Standard build (release + debug test suite)

```bash
# Release binary (setuid stripped; install handles permissions)
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Debug with tests (tests linked; 84 tests)
cmake -B build-debug -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build-debug
```

### Tests (all 3 entry points identical suite)

```bash
./build-debug/voix --run-tests    # via binary
./build-debug/test_runner         # standalone
ctest --test-dir build-debug --output-on-failure
```

## Quick Reference

| Check | Command | Expected result |
|---|---|---|
| Release build clean | `cmake --build build` | `Linking CXX executable voix`, binary executable |
| Debug tests pass | `cmake --build build-debug` | `Tests passed: 84, Failed: 0` |
| Binary executable + version | `./build/voix --version` | `Voix version 4.13.1 ...` |
| clang-tidy clean (new errors) | `clang-tidy -p build-debug src/*.cpp include/*.hpp -- -Iinclude -std=c++26` | Only pre-existing `readability-identifier-naming` (method naming convention) and `bugprone-narrowing-conversions` (cap_set_flag) warnings |
| clang-format applied | `clang-format -i src/*.cpp include/*.hpp` | No functional change |
| AUR arch expanded | `grep arch pkg/*/PKGBUILD` | `('x86_64' 'aarch64')` |
| Cross-compile mechanism | `clang++ --target=aarch64-linux-gnu ...` | Produces `ELF 64-bit LSB ... aarch64`; `armv8-a` is NOT a native clang CPU value — use target triple |

## Procedure

1. **Before changing anything**, run `git log --oneline -3` and confirm you're on `master` with clean working tree (`git status --short` clean except build artifacts, which `.gitignore` covers).
2. **After code changes**, build both: `cmake --build build` (release) and `cmake --build build-debug` (tests). Confirm 84/84.
3. **Run clang-tidy** (with `.clang-tidy` config loaded): `clang-tidy -p build-debug src/*.cpp include/*.hpp -- -Iinclude -std=c++26`. Filter out pre-existing naming/narrowing warnings; confirm zero new structural errors.
4. **Run clang-format** (`clang-format -i` on changed `.cpp`/`.hpp` files) — applied, no style-only noise.
5. **Verify binary**: `./build/voix --version` returns `v4.13.1` (version string must match `CMakeLists.txt` + `src/main.cpp` + `docs/voix.1` + `PKGBUILD` — sync them together, never individually).
6. **Tag release**: `git tag -a vX.Y.Z -m "message"`; `git push origin vX.Y.Z`. Don't delete/re-tag existing releases (version bump to new number instead).
7. **Update `.github/workflows/release.yml`** for multi-arch: `build-aarch64` job uses `--target=aarch64-linux-gnu` with `clang++-22` / `clang-22`, verifies binary architecture (`file ... | grep aarch64`), produces `voix-aarch64-bin.tar.gz` artifact.
8. **32-bit** (`i386`/`i686`) is intentionally unsupported: modern C++26 + clang-only + `libcap`/`libseccomp`/PIE + setuid-root model requires 64-bit. Documented in `packaging/README.md`.
9. **No split AUR package**: single `PKGBUILD` with `arch=('x86_64' 'aarch64')` and ARCH-triggered `build()` logic (native for x86_64, cross-compile flags for aarch64). `voix-bin` uses ARCH-triggered `source` selection (`x86_64-bin.tar.gz` vs `aarch64-bin.tar.gz`).
10. **AUR files handled by user**; this skill covers the repository-side workflow only (build/test/release/docs/version sync). Don't commit PKGBUILD changes unless explicitly directed.

## Pitfalls

- `armv8-a` is NOT a native clang CPU value: `clang --target=aarch64-linux-gnu` requires the full target triple; CMake's `-march=${VOIX_ARCH}` applies `-march=native` which overrides cross-compile. Don't mix both.
- `clang-tidy`'s `.clang-tidy` `ExtraArgs` uses quoted arrays (`['-std=c++26', '-x', 'c++']`) that conflict with the `clang-tidy ... -- -Iinclude -std=c++26` syntax; this is pre-existing, not fixable by this skill. The practical fix: verify only that NO NEW structural warnings appear beyond naming/narrowing.
- Never use machine-local paths (`/home/<user>/...`) in committed skills, docs, or scripts. All files here use repo-relative paths.
- Don't invent separate AUR packages for each architecture — AUR's `arch=` handles native vs cross natively.
- When updating version, change ALL 4 locations (`CMakeLists.txt`, `src/main.cpp`, `docs/voix.1`, `PKGBUILD` `pkgver`) atomically — partial updates break packaging and binary identity.
- `.gitignore` covers `build*` / `.cache` / `compile_commands.json`; `build/` artifacts don't appear in `git status --short`, but `git status --ignored --untracked-files=all` shows them. Don't treat untracked build artifacts as a dirty tree.
- `clang-tidy` `.clang-tidy` `ExtraArgs` (`['-std=c++26', '-x', 'c++']`) conflicts with `clang-tidy ... -- -Iinclude -std=c++26`; only verify zero NEW structural warnings (pre-existing naming/narrowing ignored). Never claim tidy passes fully when config prevents it.
- `build/` is Release (tests NOT linked); `build-debug/` is Debug (tests linked, 84/84). Don't expect `build/voix --run-tests` to work in Release builds (`BUILD_TESTING=OFF` by default).

## Verification

```bash
# Build both targets (release + debug)
cmake --build build && echo "release OK"
cmake --build build-debug && echo "tests OK (expect 84 passed, 0 failed)"

# Binary identity
./build/voix --version         # should match CMakeLists VERSION + main.cpp macro
file build/voix                # x86_64, PIE, stripped
ls -lh build/voix              # ~495K

# Multi-arch mechanism (not full artifact — requires release pipeline for binary)
clang++ --target=aarch64-linux-gnu --version   # confirms target available
# Actual aarch64 artifact produced by .github/workflows/release.yml build-aarch64 job

# Format / lint gate
clang-format -i src/*.cpp include/*.hpp
clang-tidy -p build-debug src/*.cpp include/*.hpp -- -Iinclude -std=c++26 2>&1 | grep -v "non-user" | grep -v "system-headers"
# Confirm zero new errors beyond pre-existing naming/narrowing.
```

## References

- `.github/workflows/release.yml` — `build-linux` (`x86_64`) + `build-aarch64` (cross-compile with `--target=aarch64-linux-gnu`)
- `CMakeLists.txt` — `VOIX_ARCH=native` (default); build uses `clang` + `lld`
- `docs/voix.1` — manpage version header (synced to release version)
- `packaging/README.md` — packaging instructions; see `references/multi-arch.md` for architecture-mode decision table (native vs cross-compile) and 32-bit exclusion rationale
- `pkg/voix/PKGBUILD` + `pkg/voix-bin/PKGBUILD` — AUR packaging (ARCH-triggered `build()` / `source()`)
- `docs/TESTING.md` — test harness description, 3 entry points (`test_runner`, `ctest`, `voix --run-tests`)
- `THREATS.md` §3 — seccomp black/allow profile documentation (`v4.12.0` milestone reference)

CLI options: -C/--config, -c/--check-config, -n, -s (shell), -l/--list, -E/--preserve-env, -H/--home, -i/--login, -k (invalidate auth)
