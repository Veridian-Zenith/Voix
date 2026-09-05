# Voix TODO

## Open

- [x] **Decompose `Command::execute()`**: Split the 355-line method into ten focused pipeline-stage methods (`block_signals_for_fork`, `reset_child_signals_and_umask`, `collect_sanitized_environment`, `apply_privilege_transition`, `apply_capability_drop`, `apply_environment`, `apply_resource_limits_and_close_fds`, `resolve_absolute_command`, `apply_kernel_confinement`, `do_exec`). `execute()` is now a ~30-line orchestrator. See commit 32b796d; 84/84 tests preserved (v4.12.0).
- [x] **Deterministic FD Management**: PAM session (RAII `SessionCloser` in `voix.cpp`) is opened before `fork()` and never inherited by the child; restricted-tier FD scrubbing (close_range / loop) and privileged-tier FD preservation (intentional, for pacman D-Bus hooks) are both preserved verbatim in `apply_resource_limits_and_close_fds` with an inline invariant comment. See commit 32b796d.
- [ ] **Seccomp Allowlist Mode**: Optional default-deny allowlist profile alongside the existing blacklist (see THREATS.md future considerations).
- [ ] **Multi-arch Artifacts (aarch64/arm64)**: Extend `release.yml` to a matrix (`x86_64` `x86-64` + `aarch64` `armv8-a`/`native`) via `ubuntu-24.04-arm` runners or `qemu` cross, publish `voix-aarch64-bin.tar.gz`, and expand AUR `arch` (`x86_64` → `x86_64 aarch64`) with `VOIX_ARCH` overrides; document `VOIX_ARCH` as GitHub-release knob (portable `x86-64`) vs AUR (`native` host-optimized, `arch=` declares compatibility).

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
- [x] Negative Security Testing (adversarial tests covering catastrophic command detection, path traversal, config tampering, permission bypass, blocklist evasion, command injection, environment injection, user validation injection)
- [x] Policy Validation Tool (`--check-config` now performs semantic analysis: empty ACL, unconfined root warning, redundant rules, open permissions, empty blocklist)
- [x] `-u` flag fix (rules without a target now default to root uid 0, preventing arbitrary user switching)

### v4.11.0

- [x] **Split Test Suite into Modules**: 84 tests across 8 focused files with a shared harness; suite linked into the binary so `voix --run-tests` works in Debug builds while staying fully absent from Release.
- [x] **Functional Rule Options**: `nolog` (audit suppression incl. child-side logging), `envlist` (validated KEY=VALUE injection post-sanitization), `persist` (15-minute TOCTOU-hardened tickets under `<sanctuary>/timestamp/`) all enforced; `-k` performs real ticket invalidation, standalone or with a command.
- [x] **NNP Decoupled from Seccomp**: `PR_SET_NO_NEW_PRIVS` applies unconditionally on the non-privileged tier; seccomp remains policy-controlled and extended to 19 syscalls (userfaultfd, keyctl family, io_uring, process_vm, handle-based FS) with per-architecture tolerant rule errors.
- [x] **Catastrophic Detection Overhaul**: basename-matched tools (sfdisk/cfdisk/wipefs added; whole `mkfs*` family), dd coverage of vd/mmcblk/mapper/disk aliases, rm detection of long options, combined short flags, globs, double slashes and cwd-relative targets canonicalizing to `/`.
- [x] **Blocklist `regex:` Entries**: admin regex patterns matched against the canonicalized command line; malformed patterns rejected at load time; whitespace-trim evasion closed.
- [x] **Audit Hardening**: log writer uses `O_NOFOLLOW|O_APPEND`, escapes control characters (defeats log forging), outcome-aware syslog records replace unconditional "Command executed" lines.
- [x] **First-Match Deny in `voix -l`**: listing now suppresses permits whose scope an earlier deny already wins at runtime.
- [x] **ACL Profile-Rule Parser Fix**: rules referencing `security.profiles` are no longer silently dropped by template expansion.
- [x] **Command Resolution Ownership Fix**: resolved executables verified against root ownership explicitly (post-drop euid no longer breaks resolution).
- [x] **Pre-Fork Identity Resolution**: target UID/GID/groups/home/shell resolved once in the parent; the child performs zero name-service calls between fork() and execve().
- [x] **Fail-Closed Resource Limits + Forced umask**: setrlimit failures abort instead of continuing; children run with `umask(022)` regardless of caller.
- [x] **keepenv Gating**: CLI `-E` can only request what a `keepenv` policy grant allows.
- [x] **PAM Account Validation Always Runs**: trust/nopass rules skip only the credential check; expired/locked accounts stay locked.
- [x] **Exception-Safe PAM Sessions**: RAII guard closes sessions even when command execution throws.
- [x] **Non-Clobbering Config Installs**: upgrades write `/etc/voix.conf.new` instead of overwriting live policy; sanctuary `/var/lib/voix` created by install.
- [x] **Portable Login Shells**: login mode uses the POSIX argv[0] leading-dash convention instead of the `-l` flag dash rejects.
