# Contributing to Voix

We welcome all who wish to help forge the future of Voix. To maintain the artifact's purity and security, we ask that you follow these sacred rituals.

## Table of Contents

- [The Architect's Code](#the-architects-code)
- [Development Rituals](#development-rituals)
  - [1. Preparing the Forge](#1-preparing-the-forge)
  - [2. Cleansing the Code (Tidy)](#2-cleansing-the-code-tidy)
  - [3. Testing the Artifact](#3-testing-the-artifact)
- [Roadmap and Design Decisions](#roadmap-and-design-decisions)
- [Proposing Changes](#proposing-changes)
- [Community](#community)

---

## The Architect's Code

1. **Modernity**: All code must be written in **C++26**.
2. **The Toolchain**: We exclusively use the **LLVM/Clang** toolchain. Ensure your environment matches (Clang 22+).
3. **Purity**: Before submitting your changes, run `clang-tidy` to cleanse the code of any lingering chaos.
4. **Security**: Voix is a security-critical tool. Be thorough, be careful, and always consider the principle of least privilege.

---

## Development Rituals

### 1. Preparing the Forge

```bash
cmake -B build-dbg -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug && ninja -C build-dbg -j$(nproc)
```

### 2. Cleansing the Code (Tidy)

We encourage contributors to run `clang-tidy` and address any warnings. It is essential that the checks are specified **before** the double dash (`--`), which is used to separate `clang-tidy` options from compiler-specific arguments.

A [`.clang-tidy`](.clang-tidy) configuration file has been provided in the root directory to standardize our rituals.

> [!IMPORTANT]
> The `--` separates the file list and `clang-tidy` options from compiler
> arguments like `-Iinclude` and `-std=c++26`. If you place `clang-tidy`
> options such as `--checks` *after* the `--`, they are passed to the compiler
> and ignored by `clang-tidy`, often resulting in an
> `Error: no checks enabled` message.

<details>
<summary><b>Bash ritual</b></summary>

```bash
# Manual: specify checks and build path before the compiler arguments
clang-tidy --checks='-*,bugprone-*,performance-*,readability-identifier-naming' \
           -p build-dbg \
           src/*.cpp include/*.hpp \
           -- -Iinclude -std=c++26 2>&1 | tee tidy.log

# Using the .clang-tidy config (applied automatically)
clang-tidy -p build-dbg src/*.cpp include/*.hpp -- -Iinclude -std=c++26 2>&1 | tee tidy.log
```

</details>

<details>
<summary><b>Fish ritual</b></summary>

```fish
# Manual: specify checks and build path before the compiler arguments
clang-tidy --checks='-*,bugprone-*,performance-*,readability-identifier-naming' \
           -p build-dbg \
           src/*.cpp include/*.hpp \
           -- -Iinclude -std=c++26 2>&1 | tee tidy.log

# Automated ritual using the provided .clang-tidy configuration
clang-tidy -p build-dbg src/*.cpp include/*.hpp -- -Iinclude -std=c++26 2>&1 | tee tidy.log
```

</details>

### 3. Testing the Artifact

Ensure all tests pass before proposing your changes. Tests run automatically while compiling a Debug build:

```bash
ninja -C build-dbg -j$(nproc)
```

When `BUILD_TESTING` is enabled (default for Debug builds):

- A modular test harness under `tests/` is compiled into a standalone
  `test_runner` binary registered with CTest.
- The same harness is linked into the `voix` binary itself, enabling
  `voix --run-tests`.
- The `voix` target depends on running the suite: **a failing test fails the
  build**, preventing broken binaries from being accidentally compiled or packaged.

> [!NOTE]
> In Release builds (`BUILD_TESTING=OFF`, the default) the entire harness — and
> the `--run-tests` code path — is compiled out of the shipped binary.
> `voix --run-tests` on a Release artifact reports *"Tests are not enabled in
> this build."* by design.

Enable or disable explicitly with `-DBUILD_TESTING=ON` / `-DBUILD_TESTING=OFF`.

<details>
<summary><b>Force-enabling tests in a Release build</b></summary>

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -G Ninja
ninja -C build -j$(nproc)
```

</details>

#### Running the suite manually

```bash
# Via the standalone runner (lives in the tests/ subdirectory)
./build-dbg/tests/test_runner

# Via CTest
ctest --test-dir build-dbg --output-on-failure

# Via the voix binary itself (Debug/test builds only)
./build-dbg/voix --run-tests
```

All three entry points execute the identical registered suite (84 tests).

<details>
<summary><b>Test module inventory</b></summary>

| Module file | Area covered |
| :--- | :--- |
| `test_permissions.cpp` | permit/deny, group rules, command-specific rules, first-match deny precedence, wildcard args, deny-aware `-l` listing |
| `test_config.cpp` | load success/failure, blocklist exact + `regex:` entries, malformed-regex rejection, envlist validation, rule options parsing, security-profile rule preservation, unconfined targets, schema validation |
| `test_security.cpp` | username validation, catastrophic rm/dd/mkfs/partition-tool detection incl. cwd-relative targets, blocklist integration, ticket-store roundtrip & tampering |
| `test_command.cpp` | security-profile resolution matrix (explicit / unconfined / restricted defaults) |
| `test_file_utils.cpp` | read/write, secure `O_NOFOLLOW` I/O roundtrips, symlink rejection, private-directory enforcement, command resolution incl. group-writable refusal |
| `test_logger.cpp` | timestamp format, control-character / log-forging sanitization |
| `test_system_utils.cpp` | UID/GID lookups, passwd lookups, environment application |
| `test_negative_security.cpp` | adversarial cases: encoded paths, symlink bypass, traversal args, config tampering, group spoofing, targetless-rule bypass, blocklist evasion, injection metacharacters, environment injection |

</details>

<details>
<summary><b>Runtime hardening matrix</b></summary>

Beyond unit tests, the following flows are exercised against the locally built setuid binary (see repository history for the transcript):

- `trust`/`nopass` execution
- `persist` ticket lifecycle — consume → refresh → `-k` invalidate
- `nolog` audit suppression
- `envlist` injection
- Restricted tier — `PR_SET_NO_NEW_PRIVS`, PATH override, forced umask
- Exit-code propagation
- Catastrophic-command blocks (`rm -rf /` variants, `dd` to raw devices)
- Blocklist `regex:` enforcement
- Package-manager operation under the unconfined tier
- Config-tamper rejection (symlinks)

</details>

#### Code quality

```bash
clang-tidy -p build-dbg src/*.cpp include/*.hpp -- -Iinclude -std=c++26
```

---

## Roadmap and Design Decisions

### Open

_No open items._

### Deferred (by design)

These items are intentionally not pursued due to Voix's use-case constraints:

- **Granular Security Profiles**: Binary "Privileged vs Non-Privileged" tiers are the intended model. Named profiles would add complexity without benefit for current deployment scenarios.
- **Granular Capability Management**: `CAP_DAC_READ_SEARCH` is the intentional capability scope for config reading. Individual capability raises would fragment the security model.
- **Formal State Machine Verification**: The execution pipeline's simplicity does not warrant formal verification overhead.
- **Packaging Automation**: Only AUR packaging is officially supported. Distribution-specific packaging is maintained externally.
- **Configurable Log Path**: Hardcoded `/var/log/voix.log` is intentional for safety and easy-to-discover defaults.

<details>
<summary><b>Recently completed (v4.12.0)</b></summary>

- **Decompose `Command::execute()`**: Split the 355-line method into ten focused pipeline-stage methods (`block_signals_for_fork`, `reset_child_signals_and_umask`, `collect_sanitized_environment`, `apply_privilege_transition`, `apply_capability_drop`, `apply_environment`, `apply_resource_limits_and_close_fds`, `resolve_absolute_command`, `apply_kernel_confinement`, `do_exec`). `execute()` is now a ~30-line orchestrator. See commit 32b796d; 84/84 tests preserved.
- **Deterministic FD Management**: PAM session (RAII `SessionCloser` in `voix.cpp`) is opened before `fork()` and never inherited by the child; restricted-tier FD scrubbing (close_range / loop) and privileged-tier FD preservation (intentional, for pacman D-Bus hooks) are both preserved verbatim in `apply_resource_limits_and_close_fds` with an inline invariant comment. See commit 32b796d.
- **Seccomp Allowlist Mode**: Default-deny `SCMP_ACT_KILL` profile (`seccomp_mode: allowlist`) with the 19 blacklisted syscalls permitted (`SCMP_ACT_ALLOW`). Profile-level opt-in; backward-compat `blacklist` default preserved. See `applySeccompAllowlist()` in `src/security.cpp`, `THREATS.md`, and `apply_kernel_confinement()` in `src/command.cpp`.
- **Multi-arch Artifacts (aarch64/arm64)**: AUR `arch` expanded (`x86_64` → `x86_64 aarch64`) in both `voix` and `voix-bin` PKGBUILD. `CMakeLists.txt` `VOIX_ARCH` knob documented. Native cross-compile (`clang --target=aarch64-linux-gnu`) requires the target triple and an aarch64 sysroot; `armv8-a` is not a native clang CPU name. **Release artifacts were wrong until the arm64 fix** — everything up to v4.13.3 published an x86-64 binary under the `aarch64` name (the triple was discarded by `CMakeLists.txt`'s `FORCE`-set flag cache, and the job's `file ... | grep aarch64` guard matched the `build-aarch64` path rather than the ELF). `build-aarch64` now runs natively on `ubuntu-24.04-arm` and asserts `readelf`'s `Machine:` field, and `CMakeLists.txt` selects CET (`-fcf-protection=full`) or branch protection (`-mbranch-protection=standard`) per target, since each is a hard error on the other. See the multi-arch reference under `skills/software-development/voix-release-workflow/references/`.

</details>

<details>
<summary><b>v4.11.0</b></summary>

- **Split Test Suite into Modules**: 84 tests across 8 focused files with a shared harness; suite linked into the binary so `voix --run-tests` works in Debug builds while staying fully absent from Release.
- **Functional Rule Options**: `nolog` (audit suppression incl. child-side logging), `envlist` (validated KEY=VALUE injection post-sanitization), `persist` (15-minute TOCTOU-hardened tickets under `<sanctuary>/timestamp/`) all enforced; `-k` performs real ticket invalidation, standalone or with a command.
- **NNP Decoupled from Seccomp**: `PR_SET_NO_NEW_PRIVS` applies unconditionally on the non-privileged tier; seccomp remains policy-controlled and extended to 19 syscalls (userfaultfd, keyctl family, io_uring, process_vm, handle-based FS) with per-architecture tolerant rule errors.
- **Catastrophic Detection Overhaul**: basename-matched tools (sfdisk/cfdisk/wipefs added; whole `mkfs*` family), dd coverage of vd/mmcblk/mapper/disk aliases, rm detection of long options, combined short flags, globs, double slashes and cwd-relative targets canonicalizing to `/`.
- **Blocklist `regex:` Entries**: admin regex patterns matched against the canonicalized command line; malformed patterns rejected at load time; whitespace-trim evasion closed.
- **Audit Hardening**: log writer uses `O_NOFOLLOW|O_APPEND`, escapes control characters (defeats log forging), outcome-aware syslog records replace unconditional "Command executed" lines.
- **First-Match Deny in `voix -l`**: listing now suppresses permits whose scope an earlier deny already wins at runtime.
- **ACL Profile-Rule Parser Fix**: rules referencing `security.profiles` are no longer silently dropped by template expansion.
- **Command Resolution Ownership Fix**: resolved executables verified against root ownership explicitly (post-drop euid no longer breaks resolution).
- **Pre-Fork Identity Resolution**: target UID/GID/groups/home/shell resolved once in the parent; the child performs zero name-service calls between `fork()` and `execve()`.
- **Fail-Closed Resource Limits + Forced umask**: `setrlimit` failures abort instead of continuing; children run with `umask(022)` regardless of caller.
- **keepenv Gating**: CLI `-E` can only request what a `keepenv` policy grant allows.
- **PAM Account Validation Always Runs**: trust/nopass rules skip only the credential check; expired/locked accounts stay locked.
- **Exception-Safe PAM Sessions**: RAII guard closes sessions even when command execution throws.
- **Non-Clobbering Config Installs**: upgrades write `/etc/voix.conf.new` instead of overwriting live policy; sanctuary `/var/lib/voix` created by install.
- **Portable Login Shells**: login mode uses the POSIX `argv[0]` leading-dash convention instead of the `-l` flag dash rejects.

</details>

<details>
<summary><b>Earlier milestones</b></summary>

- Path Resolution Hardening (TOCTOU protection via `O_NOFOLLOW` + `fstat()`)
- `--check-config` Mode
- Environment Sanitization Hardening
- Configurable Privileged Users
- TOCTOU-Safe Config Loading (replaced `stat()` + `LoadFile()` with `O_NOFOLLOW` + `fstat()` + fd-based read)
- Exact Command Matching for Blocklist (`isCatastrophicCommand` uses exact vector lookup, not substring matching)
- Portable Secure Memory Zeroing (`explicit_bzero` replaced with volatile pointer writes throughout)
- Negative Security Testing (adversarial tests covering catastrophic command detection, path traversal, config tampering, permission bypass, blocklist evasion, command injection, environment injection, user validation injection)
- Policy Validation Tool (`--check-config` now performs semantic analysis: empty ACL, unconfined root warning, redundant rules, open permissions, empty blocklist)
- `-u` flag fix (rules without a target now default to root uid 0, preventing arbitrary user switching)

</details>

---

## Proposing Changes

1. **Open an Issue**: Discuss your proposed changes in a new Issue or Discussion first.
2. **Create a Branch**: Use a descriptive name for your branch.
3. **Submit a Pull Request**: Provide a clear description of your changes and why they are necessary.

---

## Community

Join our [GitHub Discussions](https://github.com/Veridian-Zenith/Voix/discussions) to share ideas, ask questions, and connect with other architects.
