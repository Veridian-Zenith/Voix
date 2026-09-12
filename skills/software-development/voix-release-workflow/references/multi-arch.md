# Multi-Arch Build & Cross-Compile Reference

Decision table for architecture targets in this project.

## Architecture Modes

| Mode | Command / Flag | Binary Architecture | When Used |
|---|---|---|---|
| Native x86_64 (default) | `cmake -B build -DVOIX_ARCH=native` (default; adds `-march=native`) | `ELF 64-bit LSB ... x86-64` | Standard build (`build/`), release workflow |
| Native aarch64 (host) | `cmake -B build -DVOIX_ARCH=native` on aarch64 host | `ELF 64-bit LSB ... aarch64` | AUR native build on arm64 host |
| Cross-compile aarch64 (from x86_64 host) | `clang++ --target=aarch64-linux-gnu` (full triple required) | `ELF 64-bit ... aarch64` | `.github/workflows/release.yml` `build-aarch64`; direct mechanism verified |

Pitfall: `-march=armv8-a` or `-march=aarch64` without `--target=` does NOT cross-compile — clang applies the architecture to the native target and produces x86-64 binary with conflicting flags. The `.github/workflows/release.yml` uses `CMAKE_C_FLAGS="--target=aarch64-linux-gnu"` + `CMAKE_CXX_FLAGS="--target=aarch64-linux-gnu -std=c++26 -fexperimental-library"` to enforce cross-compilation.

## Why `armv8-a` Is Not a Native Clang CPU Value

Clang's valid CPU values (from error message): `x86-64`, `armv8-a` is NOT listed. The architecture must be specified via `--target=aarch64-linux-gnu` (target triple), not `-march=` (which selects CPU features within the current target). When cross-compiling from x86_64 to aarch64, the triple changes the binary format; `-march=` alone does not.

## AUR Architecture Handling

Both `PKGBUILD` files (`pkg/voix/PKGBUILD`, `pkg/voix-bin/PKGBUILD`) declare:

```
arch=('x86_64' 'aarch64')
```

The source-build `PKGBUILD` (`voix`) uses an ARCH-triggered `build()` function that selects native or cross-compile `CMAKE_C/CXX_FLAGS`. The pre-built binary `PKGBUILD` (`voix-bin`) selects `source` arrays (`x86_64-bin.tar.gz` vs `aarch64-bin.tar.gz`) based on `ARCH`, with a placeholder `sha256sums=('SKIP')` for the aarch64 artifact (to be updated after the release pipeline produces it).

## Release Workflow (Multi-Arch)

The `.github/workflows/release.yml` defines two independent jobs:

- `build-linux`: `ubuntu-latest`, native x86_64 (`-DVOIX_ARCH=x86-64`), produces `voix-x86_64-bin.tar.gz`
- `build-aarch64`: `ubuntu-latest`, cross-compile (`--target=aarch64-linux-gnu`), verifies binary architecture (`file ... | grep aarch64`), produces `voix-aarch64-bin.tar.gz`

Both upload artifacts and create releases (only on `v*` tag push). No 32-bit (`i386`/`i686`) job exists (intentionally excluded — see `packaging/README.md`).

## Verified Build Sizes (v4.13.1)

Measured from actual `build/voix` binary (release, `-O2` + ThinLTO + stripped):

|| Metric | Value | Source |
||---|---|---|
|| Native x86_64 binary (`build/`) | **~494 KB** | `ls -lh build/voix` (495K) |
|| Portable (`VOIX_STATIC_YAML_CPP=ON`, pre-v4.12.0 ref) | **~802 KB** (historical) / current portable also ~490 KB (shared yaml-cpp) | `packaging/README.md` |
|| LOC (`src/*.cpp` + `include/*.hpp`) | **~2,662** (2,212 impl + 450 hdr) | `cloc` / manual count |
|| LOC pre-v4.12.0 (pre-refactor docs claim) | **~3,770** (stale; updated in `THREATS.md`, `VOIX.md`) | `docs/TESTING.md` reference |

Cross-compiled `aarch64` binary produces equivalent stripped size (`~494 KB` estimated; same compiler flags). Size difference between native and cross is <10 KB.

CLI options: -C/--config, -c/--check-config, -n, -s (shell), -l/--list, -E/--preserve-env, -H/--home, -i/--login, -k (invalidate auth)
