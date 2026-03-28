# The Voix Prophecy (TODO)

This scroll tracks upcoming rituals, bindings, and enchantments intended to perfect the Keeper of Realms.

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
- [ ] **Capability-Based Ascension:** Investigate using `libcap` for fine-grained privilege management instead of raw SUID where supported by the Linux realm.
- [ ] **The Great Expansion:** Test the artifact's resilience on other Unix-like planes and ensure the build rituals remain immutable.
