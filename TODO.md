# The Voix Prophecy (TODO)

This scroll tracks upcoming rituals, bindings, and enchantments intended to perfect the Keeper of Realms.

## RECENTLY DISCOVERED VULNERABILITIES

- [x] **Critical: Fix Privilege Escalation via `LD_LIBRARY_PATH`** in environment whitelisting.
- [x] **Critical: Fix Command Injection in Login Shells (`-s` / `--login`)** arguments concatenation.
- [x] **High: Enforce absolute paths** for command resolution instead of relying on `execvp`.
- [x] **Medium: Fix TOCTOU in Path Sanitization** by using `realpath` instead of string matching.
- [x] **Medium: Prevent File Descriptor leaks** and reset inherited resource limits before `exec`.

## CRITICAL SECURITY FIXES

- [x] **Bypass Fix (`geteuid` vs `getuid`):** Correct the logic in `Security::validateContext` to use `getuid()` instead of `geteuid()` when checking the real calling user, preventing potential bypasses when invoked via other SUID binaries.
- [x] **Identity Resolution TOCTOU:** Refactor `PermissionChecker::matchRule` to avoid `getpwnam`/`getgrnam` calls during the matching phase. Resolve all identities to UIDs/GIDs during configuration loading to minimize TOCTOU windows.
- [x] **CI Build Stabilization:** Integrate `std::expected` (and `-fexperimental-library` flags) into the CI pipelines to ensure consistent builds across different compiler versions.
- [x] **Hardened Memory Allocation:** Investigated; requires integration with system allocator libraries (scudo/mimalloc). Left for later.

## ARCHITECTURAL IMPROVEMENTS

- [x] **Resource Limiting (RLIMIT):** Implement `setrlimit` calls in `Command::execute` to prevent resource exhaustion attacks by escalated processes.
- [x] **Signal Handling:** Ensure signals are properly masked/handled during the fork-exec transition to prevent premature termination or state corruption of the parent process.
- [x] **Authenticator Abstraction:** Refactor `Authenticator` into an interface to support diverse authentication realms (e.g., OIDC, SSH keys, hardware tokens) alongside PAM.
- [x] **Capability-Based Ascension:** Replace raw SUID logic with `libcap` to grant only necessary capabilities (e.g., `CAP_SETUID`, `CAP_SETGID`) to the `Voix` binary, adhering to the principle of least privilege.
- [x] **Immutable Configuration:** Implement a check to ensure `voix.conf` is owned by root and has `0600` or `0644` permissions before loading, preventing unauthorized rule injection.
- [ ] **Seccomp Sandboxing:** Implement a restrictive seccomp profile for the parent process after it has performed its initial privileged operations.

## CODE QUALITY & ROBUSTNESS

- [x] **PAM Memory Leaks:** Audit `PamUtils` to ensure all PAM-allocated strings and structures are correctly freed using `pam_set_item` or appropriate PAM free functions.
- [x] **Thread-Safe System Calls:** Review and replace non-thread-safe system calls (e.g., `strerror` with `strerror_r`, `getpwnam` with `getpwnam_r`) to ensure robustness in multi-threaded environments.
- [x] **Secure File Descriptor Handling:** Use `close_range` (where available) or a robust loop to ensure all non-essential file descriptors are closed before `execve`.
- [x] **Enhanced Config Validation:** Add more rigorous validation for configuration parameters, including path canonicalization and range checking for numeric values.
- [ ] **Fuzzing Rituals:** Establish `libFuzzer` or `AFL++` harnesses for the configuration parser and rule-matching engine.

## MODERNIZATION (C++26)

- [x] **`std::filesystem` Migration:** Replace legacy C-style file operations and manual path manipulation with `std::filesystem` for better safety and portability.
- [x] **`std::expected` for Error Handling:** Refactor internal APIs to use `std::expected` (or a backport) to provide more descriptive error states without relying on exceptions or magic return values.
- [x] **`std::format` Integration:** Modernize logging and string formatting to use `std::format` for type safety and performance.
- [x] **`std::print` Standardized Migration:** Ensure all terminal output consistently uses `std::print` and `std::println` as per C++23/26 standards.
- [ ] **Reflection-based Config Parsing:** (Future) Explore C++26 reflection (if available in LLVM) to further simplify and harden the configuration loading rituals.

## The High Rituals (Priority)

- [x] **Strengthen the Runes (Clang-Tidy):** Systematically cleanse the codebase of remaining `bugprone` and `performance` spirits identified by `clang-tidy`. Bind the code tighter to the LLVM standard.
- [x] **Contributor's Path (Tidy & Clean):** (Open Task) Contributors are encouraged to run `clang-tidy` on their contributions and the existing codebase to ensure maximum purity. Cleanups and corrections are always welcome.
- [x] **Sanitizer Orchestration:** Integrate Address and Undefined Behavior sanitizers into a dedicated `cmake` hardening profile for development (e.g., `-DVOIX_HARDEN=ON`).
- [x] **Zero-Copy Lexer:** Further refine `src/config.cpp` to use extreme zero-allocation patterns with `std::string_view` across the entire rule-matching engine.
- [x] **Binary Hardening Audit:** Implemented LLVM hardening flags (CFI, ThinLTO, Shadow Call Stack) in `CMakeLists.txt`.

## Midsummer Bindings (Medium)

- [x] **Expand the Sanctuary (`voix.conf`):**
  - Implement **Command Aliases** inside the configuration rituals.
  - Create a mechanism for preserving specific auras (environment variables) during ascension.
- [x] **Deepen the Transmutation (-s Shell):** The current `-s` invocation is rudimentary. Enhance the ritual to provide a seamless, feature-rich shell experience comparable to the old `sudo -s`.
- [x] **Global Sanctum Settings:** Fully implement the `sanctuary:` (logging) and `path:` (execution boundaries) global config runes as first-class citizens in the parser.
- [x] **Audit Sanctum:** Ensure the oracle's logs are stored in a secure sanctuary (`/var/log/voix/`) with `0600` permissions.
- [ ] **Plugins of the Void:** Design a plugin system for extending the oracle's logic without modifying the core essence.

## Winter's Rest (Low)

- [x] **The Oracle's Sight (Advanced Logging):**
  - Implement dynamic log severities (debug, info, warn, error).
  - Allow the Oracle to echo to multiple planes (syslog, `/var/log/voix.log`, stderr).
- [x] **The Great Expansion:** Test the artifact's resilience on other Unix-like planes and ensure the build rituals remain immutable.
- [ ] **The Eternal Scribe:** Implement automated man page generation from the configuration parser's internal schema.
