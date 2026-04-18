# The Voix Prophecy (TODO)

This scroll tracks upcoming rituals, bindings, and enchantments intended to perfect the Keeper of Realms.

---

## RECENTLY DISCOVERED VULNERABILITIES

- [ ] **Critical**: Fix Environment Variable Leakage during `-E` preservation (sanitize `LD_*`, `BASH_ENV`, etc.).
- [ ] **Critical**: Restrict Default Environment Whitelist to exclude compiler variables (`CC`, `CXX`, `CMAKE_*`).
- [x] **High**: Implement Strict Capability Bounding in the child process before `execv` to prevent privilege inheritance.
- [x] **High**: Adopt Command Allowlist model instead of relying on brittle `isCatastrophicCommand` string matching.
- [x] **Critical**: Fix Privilege Escalation via `LD_LIBRARY_PATH` in environment whitelisting.
- [x] **Critical**: Fix Command Injection in Login Shells (`-s` / `--login`) arguments concatenation.
- [x] **High**: Enforce absolute paths for command resolution instead of relying on `execvp`.
- [x] **Medium**: Fix TOCTOU in Path Sanitization by using `realpath` instead of string matching.
- [x] **Medium**: Prevent File Descriptor leaks and reset inherited resource limits before `exec`.

---

## CRITICAL SECURITY FIXES

- [x] **Bypass Fix (`geteuid` vs `getuid`)**: Correct logic in `Security::validateContext` to prevent bypasses.
- [x] **Identity Resolution TOCTOU**: Resolve identities to UIDs/GIDs during configuration loading.
- [x] **CI Build Stabilization**: Integrate `std::expected` for consistent builds.
- [x] **Hardened Memory Allocation**: Investigate system allocators (scudo/mimalloc).

---

## ARCHITECTURAL IMPROVEMENTS

- [x] **Resource Limiting (RLIMIT)**: Prevent resource exhaustion attacks.
- [x] **Signal Handling**: Mask/handle signals during fork-exec.
- [x] **Authenticator Abstraction**: Support diverse authentication realms.
- [x] **Capability-Based Ascension**: Use `libcap` to grant only necessary capabilities.
- [x] **Immutable Configuration**: Ensure `voix.conf` is owned by root and has proper permissions.
- [x] **Seccomp Sandboxing**: Restrictive profile for sensitive processes.

---

## CODE QUALITY & ROBUSTNESS

- [x] **PAM Memory Leaks**: Audit `PamUtils` and ensure proper freeing.
- [x] **Thread-Safe System Calls**: Replace non-thread-safe calls with thread-safe alternatives.
- [x] **Secure File Descriptor Handling**: Use `close_range` to close non-essential FDs.
- [x] **Enhanced Config Validation**: Rigorous validation for configuration parameters.
- [-] **Fuzzing Rituals**: `libFuzzer` harnesses for config parser (Deferred).
- [x] **RAII for C-APIs**: RAII wrappers for `cap_t` and `pam_handle`.
- [x] **Modernize String Handling**: Use `std::string` or `std::string_view` for safety.
- [x] **Type-Safe Casts**: Replace C-style casts with C++ casts.

---

## MODERNIZATION (C++26)

- [x] **`std::filesystem` Migration**: Safer file operations and path manipulation.
- [x] **`std::expected` for Error Handling**: Descriptive error states.
- [x] **`std::format` Integration**: Type-safe logging and string formatting.
- [x] **`std::print` Standardized Migration**: Use `std::print` for all terminal output.
- [ ] **Reflection-based Config Parsing**: (Future) Explore C++26 reflection.

---

## THE HIGH RITUALS (Priority)

- [x] **Strengthen the Runes (Clang-Tidy)**: Clean codebase of `bugprone` and `performance` spirits.
- [x] **Contributor's Path (Tidy & Clean)**: Maintain codebase purity.
- [x] **Sanitizer Orchestration**: Integrate Address and Undefined Behavior sanitizers.
- [x] **Zero-Copy Lexer**: Use `std::string_view` for config parsing.
- [x] **Binary Hardening Audit**: Implemented CFI, ThinLTO, Shadow Call Stack.

---

## MIDSUMMER BINDINGS (Medium)

- [x] **Expand the Sanctuary (`voix.conf`)**:
  - Implement Command Aliases.
  - Preserve specific environment variables during ascension.
- [x] **Deepen the Transmutation (-s Shell)**: Feature-rich shell experience.
- [x] **Global Sanctum Settings**: Fully implement `sanctuary:` and `path:` settings.
- [x] **Audit Sanctum**: Secure `/var/log/voix/` permissions.
- [-] **Plugins of the Void**: Plugin system (Deferred).

---

## WINTER'S REST (Low)

- [x] **The Oracle's Sight (Advanced Logging)**: Dynamic log severities and multi-plane echoing.
- [x] **The Great Expansion**: Test resilience on other Unix-like planes.
- [-] **The Eternal Scribe**: Automated man page generation (Deferred).
