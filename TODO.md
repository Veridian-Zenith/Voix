# The Voix Prophecy (TODO)

This scroll tracks upcoming rituals, bindings, and enchantments intended to perfect the Keeper of Realms.

## CRITICAL SECURITY FIXES

- [x] **Bypass Fix (`geteuid` vs `getuid`):** Correct the logic in `Security::validateContext` to use `getuid()` instead of `geteuid()` when checking the real calling user, preventing potential bypasses when invoked via other SUID binaries.
- [ ] **Identity Resolution TOCTOU:** Refactor `PermissionChecker::matchRule` to avoid `getpwnam`/`getgrnam` calls during the matching phase. Resolve all identities to UIDs/GIDs during configuration loading to minimize TOCTOU windows.

## ARCHITECTURAL IMPROVEMENTS

- [ ] **Resource Limiting (RLIMIT):** Implement `setrlimit` calls in `Command::execute` to prevent resource exhaustion attacks by escalated processes.
- [ ] **Signal Handling:** Ensure signals are properly masked/handled during the fork-exec transition to prevent premature termination or state corruption of the parent process.
- [ ] **Authenticator Abstraction:** Refactor `Authenticator` into an interface to support diverse authentication realms (e.g., OIDC, SSH keys, hardware tokens) alongside PAM.
- [ ] **Capability-Based Ascension:** Replace raw SUID logic with `libcap` to grant only necessary capabilities (e.g., `CAP_SETUID`, `CAP_SETGID`) to the `Voix` binary, adhering to the principle of least privilege.
- [ ] **Immutable Configuration:** Implement a check to ensure `voix.conf` is owned by root and has `0600` or `0644` permissions before loading, preventing unauthorized rule injection.

## CODE QUALITY & ROBUSTNESS

- [x] **PAM Memory Leaks:** Audit `PamUtils` to ensure all PAM-allocated strings and structures are correctly freed using `pam_set_item` or appropriate PAM free functions.
- [x] **Thread-Safe System Calls:** Review and replace non-thread-safe system calls (e.g., `strerror` with `strerror_r`, `getpwnam` with `getpwnam_r`) to ensure robustness in multi-threaded environments.
- [x] **Secure File Descriptor Handling:** Use `close_range` (where available) or a robust loop to ensure all non-essential file descriptors are closed before `execve`.
- [x] **Enhanced Config Validation:** Add more rigorous validation for configuration parameters, including path canonicalization and range checking for numeric values.

## MODERNIZATION (C++26)

- [x] **`std::filesystem` Migration:** Replace legacy C-style file operations and manual path manipulation with `std::filesystem` for better safety and portability.
- [x] **`std::expected` for Error Handling:** Refactor internal APIs to use `std::expected` (or a backport) to provide more descriptive error states without relying on exceptions or magic return values.
- [ ] **`std::format` Integration:** Modernize logging and string formatting to use `std::format` for type safety and performance.

## The High Rituals (Priority)

- [ ] **Strengthen the Runes (Clang-Tidy):** Systematically cleanse the codebase of remaining `bugprone` and `performance` spirits identified by `clang-tidy`. Bind the code tighter to the LLVM standard.
- [ ] **Sanitizer Orchestration:** Integrate Address and Undefined Behavior sanitizers into a dedicated `cmake` hardening profile for development (e.g., `-DVOIX_HARDEN=ON`).
- [ ] **Zero-Copy Lexer:** Further refine `src/config.cpp` to use extreme zero-allocation patterns with `std::string_view` across the entire rule-matching engine.

## Midsummer Bindings (Medium)

- [ ] **Expand the Sanctuary (`voix.conf`):**
  - Implement **Command Aliases** inside the configuration rituals.
  - Create a mechanism for preserving specific auras (environment variables) during ascension.
- [ ] **Deepen the Transmutation (-s Shell):** The current `-s` invocation is rudimentary. Enhance the ritual to provide a seamless, feature-rich shell experience comparable to the old `sudo -s`.
- [ ] **Global Sanctum Settings:** Fully implement the `sanctuary:` (logging) and `path:` (execution boundaries) global config runes as first-class citizens in the parser.
- [ ] **Audit Sanctum:** Ensure the oracle's logs are stored in a secure sanctuary (`/var/log/voix/`) with `0600` permissions.

## Winter's Rest (Low)

- [ ] **The Oracle's Sight (Advanced Logging):**
  - Implement dynamic log severities (debug, info, warn, error).
  - Allow the Oracle to echo to multiple planes (syslog, `/var/log/voix.log`, stderr).
- [ ] **The Great Expansion:** Test the artifact's resilience on other Unix-like planes and ensure the build rituals remain immutable.
