# Multi-Arch Build & Cross-Compile Reference

Decision table for architecture targets in this project.

## Architecture Modes

| Mode | Command / Flag | Binary Architecture | When Used |
|---|---|---|---|
| Native x86_64 (default) | `cmake -B build -DVOIX_ARCH=native` (default; adds `-march=native`) | `ELF 64-bit LSB ... x86-64` | Standard build (`build/`), release workflow |
| Native aarch64 (host) | `cmake -B build -DVOIX_ARCH=native` on aarch64 host | `ELF 64-bit LSB ... aarch64` | AUR native build on arm64 host |
| Native aarch64 (arm64 runner) | `runs-on: ubuntu-24.04-arm`; `cmake -DVOIX_ARCH=armv8-a` | `ELF 64-bit LSB ... ARM aarch64` — verified | `.github/workflows/release.yml` `build-aarch64` |
| Cross-compile aarch64 (from x86_64 host) | `clang++ --target=aarch64-linux-gnu` (full triple required) | codegen only: produces aarch64 objects, but the x86_64 runners have no aarch64 sysroot/libraries, and two project flags are x86-only | not used — this is what silently produced the v4.13.3 defect below |

Pitfall: `-march=armv8-a` or `-march=aarch64` without `--target=` does NOT cross-compile — clang applies the architecture to the native target and produces x86-64 binary with conflicting flags.

### The v4.13.3 aarch64 defect, and its resolution (verified 2026-10-12)

**What went wrong.** The `build-aarch64` job never cross-compiled. Three
independent faults compounded, and only the first was visible:

1. The triple never reached the compiler. The job passed
   `--target=aarch64-linux-gnu` through `CMAKE_C_FLAGS` / `CMAKE_CXX_FLAGS`, but
   `CMakeLists.txt` lines 8-11 `FORCE`-override those cache entries (and line 69
   re-sets `CMAKE_CXX_FLAGS`), so the flags were discarded and the job produced a
   second native x86-64 build.
2. The guard could not fail. `file build-aarch64/voix | grep -q aarch64` matches
   the *path* — `build-aarch64` contains the substring "aarch64" — and never
   inspects the ELF machine type.
3. The project's own flags were x86-only, so even a correct triple could not have
   compiled: `-fcf-protection=full` is a hard error on aarch64
   (`option 'cf-protection=return' cannot be specified on this target`), and
   `-march=native` resolves to an x86 CPU name there.

**Evidence.** The published `voix-aarch64-bin.tar.gz` extracted an x86-64 ELF:
`readelf -h` reported `Machine: Advanced Micro Devices X86-64`
(`e_machine = 0x003e`), 802,552 B.

**Fix shipped.** The job now builds natively on GitHub's arm64 runner
(`ubuntu-24.04-arm`, free for public repositories), so no triple or sysroot is
needed. `CMakeLists.txt` selects the control-flow flag from
`CMAKE_SYSTEM_PROCESSOR` — `-fcf-protection=full` on x86_64,
`-mbranch-protection=standard` on aarch64, since each is a hard error on the
other. Both jobs now assert `readelf -h`'s `Machine:` field instead of grepping
`file` output for a substring.

Verified by downloading that run's artifact: `file` reports
`ELF 64-bit LSB pie executable, ARM aarch64 ... interpreter
/lib/ld-linux-aarch64.so.1`, `readelf` `Machine: AArch64`, `e_machine = 0xb7`,
and the binary contains the `4.13.3` version string.

**Known gap — aarch64 has no CET analogue.** `-mbranch-protection=standard` is
accepted at the `armv8-a` baseline but emits *nothing*: BTI needs ARMv8.5 (or an
explicit `+bti`) and PAC needs `+pauth`, so the verified aarch64 binary contains
0 `bti`, 0 `paciasp`, 0 `autiasp` and no `GNU_PROPERTY_AARCH64_FEATURE_1_AND`
note. Raising `VOIX_ARCH` to `armv8-a+bti+pauth` (or `armv8.5-a`) would emit
them; BTI/PAC use the HINT space and are NOPs on older CPUs, but this also
raises the declared CPU baseline, and linking the non-BTI `libyaml-cpp.a` may
clear the property anyway. Decide deliberately — it is a compatibility/hardening
trade-off, not a free win.

## `armv8-a` Is Valid Only For An aarch64 *Target*

`armv8-a` is a perfectly valid clang CPU name **for an aarch64 target** —
`clang++ --target=aarch64-linux-gnu -march=armv8-a` compiles fine and produces
ARM aarch64 objects. What fails is `-march=armv8-a` on the *native* x86_64
target, where clang lists x86 CPU names and rejects it (the observed error
enumerated `x86-64`, and `-march=native` there resolved to `alderlake`). The
architecture must therefore be selected by the target triple, not `-march=
` alone; `-march=` only tunes CPU features within the chosen target.

## AUR Architecture Handling

Both `PKGBUILD` files (`pkg/voix/PKGBUILD`, `pkg/voix-bin/PKGBUILD`) declare:

```
arch=('x86_64' 'aarch64')
```

The source-build `PKGBUILD` (`voix`) uses an ARCH-triggered `build()` function that selects native or cross-compile `CMAKE_C/CXX_FLAGS`. The pre-built binary `PKGBUILD` (`voix-bin`) selects `source` arrays (`x86_64-bin.tar.gz` vs `aarch64-bin.tar.gz`) based on `ARCH`, each with its own real `sha256sums_<arch>` entry (and `SKIP` for the `.asc`, which is the signature itself).

## Release Workflow (Multi-Arch)

The `.github/workflows/release.yml` defines two independent jobs:

- `build-linux`: `ubuntu-latest`, native x86_64 (`-DVOIX_ARCH=x86-64`), produces `voix-x86_64-bin.tar.gz`
- `build-aarch64`: `ubuntu-24.04-arm`, native aarch64 (`-DVOIX_ARCH=armv8-a`, `-DVOIX_STATIC_YAML_CPP=ON`), asserts `readelf -h`'s `Machine:` field is `AArch64`, produces `voix-aarch64-bin.tar.gz`

Both upload artifacts and create releases (only on `v*` tag push). No 32-bit (`i386`/`i686`) job exists (intentionally excluded — see `packaging/README.md`).

## Verified Build Sizes (v4.13.3)

Measured from the actual `build/voix` binary and from `makepkg -s` in `pkg/voix` and `pkg/voix-bin`
(release, `-O2` + ThinLTO + stripped):

| Metric | Value | Source |
| :--- | :--- | :--- |
| Native x86_64 binary (`build/`) | **511,352 B** (~499 KiB) | `ls -la build/voix`; identical size from the `pkg/voix` build |
| Distro package (`pkg/voix`, dynamic `yaml-cpp`) | **236,004 B** package (`du -sh` 232K) / **518,176 B** installed | `makepkg -s`; `.PKGINFO` `size =` |
| Portable binary, x86_64 (`pkg/voix-bin`, bundled `yaml-cpp`) | **794,392 B** (~776 KiB) | `tar tzvf voix-x86_64-bin.tar.gz` |
| Portable binary, aarch64 (`pkg/voix-bin`) | **754,200 B** (~737 KiB) | native arm64 CI artifact, `readelf` `Machine: AArch64` |
| Portable package | **340,155 B** package (`du -sh` 336K) / **801,216 B** installed | `makepkg -s`; `.PKGINFO` `size =` |
| LOC (`src/*.cpp` + `include/*.hpp`) | **4,124** (2,887 impl + 1,237 hdr) | `wc -l src/*.cpp include/*.hpp \| tail -1` |
| Test suite | **1,930** lines / **84** tests | `wc -l tests/*.cpp tests/*.hpp` |

Bundling `yaml-cpp` adds ~283 KB (794 KB vs 511 KB) but removes the versioned
`libyaml-cpp.so.N` soname requirement — the distro build links `libyaml-cpp`
dynamically, the portable one does not.

The `aarch64` figures come from the native arm64 runner (no aarch64 sysroot
exists on an x86_64 host, so they cannot be reproduced locally). Any
`voix-x86_64-bin.tar.gz` or `voix-aarch64-bin.tar.gz` published *before* the fix
above is not architecture-correct: the v4.13.3 `aarch64` asset is an x86-64 ELF
(802,552 B), so a checksum pinned against it ships a binary that cannot run on
aarch64. Re-cut the release after the fix.
