# The Voix Prophecy (TODO)

This scroll tracks upcoming rituals, bindings, and enchantments intended to perfect the Keeper of Realms.

## The High Rituals (Priority)

- [ ] **Strengthen the Runes (Clang-Tidy):** Systematically cleanse the codebase of remaining `bugprone` and `performance` spirits identified by `clang-tidy`. Bind the code tighter to the LLVM standard.

## Midsummer Bindings (Medium)

- [ ] **Expand the Sanctuary (`voix.conf`):**
  - Carve support for **Command Aliases** inside the configuration rituals.
  - Implement a mechanism for preserving specific auras (environment variables) during ascension.
- [ ] **Deepen the Transmutation (-s Shell):** The current `-s` invocation is rudimentary. Enhance the ritual to provide a seamless, feature-rich shell experience comparable to the old `sudo -s`.
- [ ] **Global Sanctum Settings:** Fully implement the `sanctuary:` (logging) and `path:` (execution boundaries) global config runes as first-class citizens in the parser.

## Winter's Rest (Low)

- [ ] **The Oracle's Sight (Advanced Logging):**
  - Implement dynamic log severities (debug, info, warn, error).
  - Allow the Oracle to echo to multiple planes (syslog, `/var/log/voix.log`, stderr).
- [ ] **Expand the Boundaries:** Test the artifact's resilience on other Unix-like planes and ensure the build rituals hold true.
