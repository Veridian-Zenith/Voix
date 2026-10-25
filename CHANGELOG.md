# Changelog

All notable changes to Voix are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- Resolve every requested command to a canonical, root-owned executable
  before policy evaluation. Absolute paths, relative paths, and bare names
  now receive the same validation, and ACL rules are matched against the
  canonical path.
- Pin the validated executable inode and execute it with `fexecve(2)`.
  Replacing the path between validation and execution no longer changes
  which file runs.
- Remove the passwordless-target authentication bypass. A target account
  without a usable password no longer skips the caller credential check.
- Validate the target account with a separate PAM handle. Target account
  validation is not treated as proof that credentials were verified.
- Scope `persist` tickets to the caller/target UID pair and mint them only
  after a real `pam_authenticate(3)` success. Trust/nopass/root skips and
  reused tickets no longer bootstrap or refresh a ticket.
- Consult persisted tickets before `-n` rejects an invocation, so
  non-interactive runs can reuse an existing ticket but can never prompt.
- Force `HOME` and `SHELL` to the target's values for login shells (`-i`),
  so a `keepenv` grant or unconfined target cannot make the target shell
  read the caller's startup files.
- Reject `-C` configuration paths unless every component is absolute,
  root-owned, non-group/world-writable, and free of symlinks.
- Change the built-in default sanctuary from `/tmp` to `/var/lib/voix`.
- Ship a conservative sample policy: no default `wheel` trust grant, no
  unconfined targets, and an empty ACL that must be configured explicitly.

### Added

- Stable process exit codes based on `sysexits(3)` (`64` usage, `70`
  internal, `77` not permitted, `78` configuration, `126` cannot execute,
  `127` not found). See `docs/CLI.md`.
- `security.profiles.<name>.seccomp_allow`: extra syscall names for
  `seccomp_mode: allowlist`, validated by `--check-config`.
- Consistent user-facing diagnostics: `voix: error:` plus an optional
  `voix: hint:` remediation line. Fatal errors are printed even when
  `core.suppress_stderr` is enabled.
- Stable audit event codes (`command.requested`, `command.denied`,
  `auth.failed`, and others) in security log records, with the PID included
  in every log line. Audit records now go to both `/var/log/voix.log` and
  syslog.
- `Config::last_error()` so configuration failures report the precise cause
  instead of a generic message.

### Fixed

- Rebuild seccomp allowlist mode around a usable default-deny baseline. The
  previous set permitted only the syscalls the blacklist kills and omitted
  `execve`/`execveat`, so the target was killed before it could start.
- Honor `scrub_environment: false` in the execution path. The setting was
  parsed but ignored, so a profile could not grant environment preservation.
- Reject an unrecognized `seccomp_mode` at configuration time instead of
  silently running without a filter, and fail closed if one reaches the child.
- Canonicalize exact blocklist entries when matching, so `/bin/sh` also
  blocks equivalent spellings and merged-`/usr` aliases.
- Preserve the pinned executable descriptor while scrubbing inherited file
  descriptors on the restricted tier. The scrub moved it to fd 3 but the
  executor still passed the old descriptor number to `fexecve(2)`, so every
  restricted execution failed with `EBADF`; the preserved descriptor is now
  returned and used.
- Write the execution audit record before the privilege transition and file
  descriptor scrub, so the root-owned log file remains writable.
- Replace the stateful libc `syslog(3)` call with a per-record `/dev/log`
  datagram. A cached syslog descriptor inherited across `fork()` could refer
  to the pinned executable after the FD scrub, and `syslog(3)` would close
  it; the stateless sender cannot clobber the executable descriptor and does
  not depend on libc-private state.
- Report fork, waitpid, privilege-transition, and `fexecve(2)` failures with
  actionable messages and meaningful exit codes instead of a generic `1`.
- Exit with `126` (no-exec) when a seccomp filter cannot be built or loaded,
  matching the documented contract.

### Tests

- Add executable replacement/TOCTOU coverage, absolute/relative/symlink
  resolution coverage, ACL canonicalization coverage, ticket scope and
  credential-mode ordering coverage, login-shell `HOME`/`SHELL` coverage,
  and configuration path trust coverage.
- Add end-to-end seccomp coverage: a real dynamically linked binary must
  start and exit 0 under both blacklist and allowlist mode, and
  `seccomp_allow`/`seccomp_mode` misconfigurations must be rejected.
- Add environment-sanitization coverage for `scrub_environment` and `keepenv`.
- Add an end-to-end integration suite that runs the real
  `resolve -> open -> pin -> fork -> privilege transition -> FD scrub ->
  seccomp -> fexecve(2)` path unprivileged: exit-status propagation,
  executable replacement (TOCTOU) refusal, `HOME` and environment delivery,
  blacklist/allowlist execution, and ACL denial before any process is
  created.

### Documentation

- Document the new resolution, authentication, ticket, environment, and
  configuration-path behavior.

## [4.13.3] - 2026-10-12

### Fixed

- Correct the aarch64 release build to run on a native arm64 runner and
  verify the ELF machine type.
- Correct documentation for security behavior, package sizes, and build
  paths.
