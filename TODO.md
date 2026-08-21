# Voix TODO

## Open

- [ ] **Deterministic FD Management**: Full audit of internal file descriptors (PAM handles, config streams) to ensure all are `O_CLOEXEC`. Implement strict FD-closing invariant before `execve`.
- [ ] **Split Monolithic Test File**: Break `tests/test_runner.cpp` (~1440 lines, 80 tests) into per-module test files.
- [ ] **Decompose `Command::execute()`**: Split the ~276-line method into smaller focused functions (signal setup, privilege transition, env sanitization, FD closing, seccomp).

## Deferred (by design)

These items are intentionally not pursued due to Voix's use-case constraints:

- [ ] ~~**Granular Security Profiles**~~: Binary "Privileged vs Non-Privileged" tiers are the intended model. Named profiles would add complexity without benefit for current deployment scenarios.
- [ ] ~~**Granular Capability Management**~~: `CAP_DAC_READ_SEARCH` is the intentional capability scope for config reading. Individual capability raises would fragment the security model.
- [ ] ~~**Formal State Machine Verification**~~: The execution pipeline's simplicity does not warrant formal verification overhead.
- [ ] ~~**Packaging Automation**~~: Only AUR packaging is officially supported. Distribution-specific packaging is maintained externally.
- [ ] ~~**Configurable Log Path**~~: Hardcoded `/var/log/voix.log` is intentional for safety and easy-to-discover defaults.

## Completed

- [x] Path Resolution Hardening (TOCTOU protection via `O_NOFOLLOW` + `fstat()`)
- [x] `--check-config` Mode
- [x] Environment Sanitization Hardening
- [x] Configurable Privileged Users
- [x] TOCTOU-Safe Config Loading (replaced `stat()` + `LoadFile()` with `O_NOFOLLOW` + `fstat()` + fd-based read)
- [x] Exact Command Matching for Blocklist (`isCatastrophicCommand` uses exact vector lookup, not substring matching)
- [x] Portable Secure Memory Zeroing (`explicit_bzero` replaced with volatile pointer writes throughout)
- [x] Negative Security Testing (15 exploit-pattern tests covering catastrophic command detection, path traversal, config tampering, permission bypass, blocklist evasion, command injection, environment injection, user validation injection)
- [x] Policy Validation Tool (`--check-config` now performs semantic analysis: empty ACL, unconfined root warning, redundant rules, open permissions, empty blocklist)
- [x] `-u` flag fix (rules without a target now default to root uid 0, preventing arbitrary user switching)
