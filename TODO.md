# Voix TODO

Living tracker for the security-hardening branch and the work that follows it.
Update this file whenever an item's state changes, and record every
user-visible change in [`CHANGELOG.md`](CHANGELOG.md).

| Field | Value |
| :--- | :--- |
| **Branch** | `security/p0-hardening` |
| **Base** | `origin/master` at `8d03947` (the local `master` ref is one commit behind at `96668af`) |
| **Development version** | `4.14.0-beta.1` (test/beta; `4.13.3` is the last release) |
| **Status** | P0 hardening complete, build green (`121/121` tests), ready for review |
| **Last updated** | 2026-10-25 |

Legend: `[ ]` open · `[~]` in progress · `[x]` done · `[>]` deferred by design

---

## 1. Merge checklist

- [ ] Open a pull request for `security/p0-hardening` against `master`. No PR
  exists yet; the branch is only pushed to `origin`.
- [ ] Confirm CI is green on the branch: `Test Suite`, `CodeQL Analysis`, and
  the repository's CodeQL default setup.
- [ ] Re-run the local gate from a clean build directory (see
  [§6](#6-verification-gate)).
- [ ] Run `clang-tidy` over `src/*.cpp include/*.hpp`; keep it warning-free.
- [ ] Close dependabot PR #32 (`github/codeql-action` 4.38.3 → 4.39.0) as
  superseded. The bump is already on this branch as `e8d93c7`.
- [ ] Re-check the CodeQL "Uncontrolled process operation" alert after the
  branch lands. Both `execv` call sites from `master` are now `fexecve` on a
  pinned, inode-verified descriptor, so no suppression is expected unless a
  new alert appears.
- [ ] Decide the release vehicle. The policy defaults and exit codes are
  breaking, so `4.14.0` is the natural next release; `4.14.0-beta.1` is
  intentionally not a release tag.
- [ ] When promoting out of beta, update `packaging/` `pkgver`, the manpage
  date, and the release notes. AUR `pkgver` cannot contain `-`, so use a form
  such as `4.14.0beta1` if the beta string must be packaged.
- [ ] Confirm the shipped `config/voix.conf` remains closed by default and
  document the migration for existing operators: empty ACL, no implicit
  `wheel` trust, no unconfined targets, `/var/lib/voix` sanctuary, and the new
  `sysexits(3)` exit codes.

---

## 2. P1 — finish before merge

### 2.1 `-s` must use the target account's login shell

- **Problem:** `-s` prefers the caller's `$SHELL` and only falls back to the
  *invoking* user's passwd shell (`src/main.cpp`). Ascending to another
  account therefore runs a shell the target may not own, and `$SHELL` is
  caller-controlled. `-i` without a command already uses the target's passwd
  shell, so the two interactive paths disagree.
- **Fix:** resolve the target identity first, then use the target's passwd
  shell (final fallback `/bin/sh`) for both `-s` and `-i` without a command.
  Do not consult `$SHELL` for a privilege transition. If compatibility
  requires honoring it, gate it behind an explicit policy grant.
- **Acceptance:** `voix -u other -s` executes `other`'s passwd shell; a caller
  with `SHELL=/tmp/evil` cannot influence the executed binary; login-shell
  `HOME`/`SHELL` tests cover both paths; the target shell still has to pass
  the root-owned, non-writable executable check.
- **Files:** `src/main.cpp`, `src/voix.cpp`, `include/system_identity.hpp`,
  `tests/test_command.cpp`, `tests/test_integration.cpp`, `docs/CLI.md`,
  `THREATS.md` §7.

### 2.2 Validate the sanctuary's ownership and parent chain

- **Problem:** `Config::validate()` only checks that `core.sanctuary` is a
  directory (`src/config.cpp`). A root-owned config can point at `/tmp` or
  another attacker-writable directory, letting an unprivileged user tamper
  with timestamp tickets.
- **Fix:** extract the trust walk used for `-C`
  (`FileUtils::is_trusted_config_path`) into a shared helper and apply it to
  the sanctuary: every component root-owned, not group/world-writable, and
  free of symlinks (or resolve symlinks and validate the target). Validate
  before any ticket is read or written.
- **Acceptance:** `--check-config` rejects `/tmp`, symlinked sanctuaries, and
  any path with a non-root or writable component; the shipped
  `/var/lib/voix` passes; regression tests cover each rejection.
- **Files:** `src/config.cpp`, `src/file_utils.cpp`,
  `include/file_utils.hpp`, `tests/test_config.cpp`,
  `tests/test_file_utils.cpp`, `THREATS.md` §7.

### 2.3 Broaden `-l` deny-awareness

- **Problem:** `PermissionChecker::list_permitted_rules()` suppresses a permit
  only when an earlier deny has an *identical* command/args/target scope
  (`src/permission_checker.cpp`). Broader denies — a deny with empty args, or
  a deny whose scope covers the permit — are not reflected, so `-l` can
  advertise commands that runtime first-match denies.
- **Fix:** evaluate each permit against the same ordered rule list the
  executor uses and list it only when the first matching rule for its concrete
  scope is a permit. Where a rule scope is broader than a single command line,
  either narrow the listing to fully determined scopes or mark the entry as
  conditional instead of overstating it.
- **Acceptance:** tests cover (a) deny with empty args before a permit with
  args, (b) deny for a different target, (c) deny after permit (permit should
  still list), and (d) exact-scope behavior unchanged.
- **Files:** `src/permission_checker.cpp`,
  `include/permission_checker.hpp`, `tests/test_permissions.cpp`,
  `docs/CLI.md`, `THREATS.md` §7.

---

## 3. P2 — follow-up hardening

- [ ] **Seccomp allowlist presets.** Document and test a small set of
  `seccomp_allow` bundles (for example `shell`, `build`, `network-client`) so
  operators do not have to discover syscalls by trial and error. Keep the
  default-deny baseline unchanged.
- [ ] **Allowlist coverage for process creation.** Add an integration test
  that grants `fork`/`clone`/`execve` through `seccomp_allow` and verifies a
  shell can spawn a child, plus a negative test that the same command is
  killed without the grant.
- [ ] **Parent-side audit outcome.** The child logs "executing command" before
  the transition. Add a parent-side outcome record (exit status, signal,
  duration) so the audit trail distinguishes attempted from completed
  executions without trusting the child.
- [ ] **Syslog sink test.** The logger now sends a per-record `/dev/log`
  datagram. Add a test with a temporary `AF_UNIX` socket (injectable path) that
  asserts the `<PRI>` prefix and message body without requiring a running
  syslog daemon.
- [ ] **Config fuzzing.** Add a libFuzzer/AFL harness for the YAML loader and
  rule parser, seeded with `config/voix.conf`; run it on a schedule.
- [ ] **PAM integration tests.** Exercise the real PAM stack (caller and
  target handles, `pam_acct_mgmt`, ticket ordering) in a disposable container;
  keep it out of the default unit run.
- [ ] **Privileged-tier end-to-end test.** Run the setuid transition in a
  root-owned VM/container and assert the child's UID/GID/groups, inherited
  FDs, and capability state. The current integration suite runs unprivileged
  by design.
- [ ] **`-E` semantics.** Either implement the documented `-E` behavior or
  remove the flag; today it is accepted and ignored (`THREATS.md` §7). Decide
  before the next release so the CLI and docs agree.
- [ ] **Catastrophic-gate depth.** The gate inspects only the directly
  requested command; a permitted shell can invoke blocked tools. Document a
  "no shells" policy pattern and consider an opt-in wrapper check.
- [ ] **Multi-arch release verification.** Add a CI smoke test that runs
  `voix --version` from both release tarballs and asserts the `Machine:` field
  matches the artifact name. The v4.13.3 `aarch64` asset was an x86-64 ELF.

---

## 4. Completed on this branch (P0)

### `8300d7d` — end-to-end execution coverage + FD/syslog fixes

- Added `tests/test_integration.cpp`: unprivileged
  `resolve → open → pin → fork → privilege transition → FD scrub → seccomp →
  fexecve` coverage, including TOCTOU replacement refusal, exit-status
  propagation, `HOME`/environment delivery, blacklist/allowlist execution, and
  ACL denial before process creation.
- Fixed `apply_resource_limits_and_close_fds()` so it returns the preserved
  descriptor; `do_exec()` no longer receives the closed pre-scrub fd number
  (every restricted execution previously failed with `EBADF`).
- Moved the execution audit record before the privilege transition and FD
  scrub, so the root-owned log file remains writable.
- Replaced stateful libc `syslog(3)` with a stateless `/dev/log` datagram so a
  cached descriptor cannot close the pinned executable after `fork()`.

### `e8d93c7` — dependabot cherry-pick

- `github/codeql-action` 4.38.3 → 4.39.0 (`-x` attribution preserved);
  supersedes PR #32.

### `be38a80` — seccomp and environment profile settings

- Rebuilt allowlist mode as default-deny `SCMP_ACT_KILL_PROCESS` plus a usable
  baseline and per-profile `seccomp_allow`.
- Unknown `seccomp_mode` is a configuration error (was fail-open).
- `scrub_environment: false` is honored as a profile-level environment grant.
- Extracted `Command::sanitize_environment()` for unit testing; designated
  initializers for `SecurityProfile`; exit `126` when seccomp cannot load.

### `bf339dc` — documentation

- Documented the hardened execution/auth/diagnostics behavior in
  `docs/CONFIG.md`, `docs/CLI.md`, and `THREATS.md`; introduced
  `CHANGELOG.md`.

### `50b8759` — executable pinning and canonical policy paths

- `resolve_executable()` returns the realpath for execution and a
  directory-canonical `policy_path` for ACL/blocklist matching (preserves
  multicall applet names).
- `open_executable()` re-checks device/inode/ownership/mode on the descriptor;
  `fexecve()` executes the pinned inode; fd 3 is preserved on the restricted
  tier.

### `f9f0428` — authentication, config trust, diagnostics

- Removed the passwordless-target bypass; caller and target PAM handles are
  validated separately.
- Scoped `persist` tickets to caller/target UID pairs; tickets are minted only
  after a real `pam_authenticate`.
- `-n` consults persisted tickets but never prompts; trusted `-C` paths;
  closed-by-default policy; `/var/lib/voix` sanctuary.
- `sysexits(3)` exit codes; stable audit codes; PID in every log line;
  `Config::last_error()`; `voix: error:` / `voix: hint:` diagnostics.

### Baseline

- `96668af` (`master`) — documentation corrections for security, auth, and CLI
  claims. It is an ancestor of the branch base `8d03947`.

---

## 5. Deferred by design

- **Granular security profiles / capabilities.** The privileged vs restricted
  tier model is intentional; named capability fragments would enlarge the
  policy surface.
- **Formal state-machine verification.** The execution pipeline is small
  enough that review plus integration tests are the chosen assurance path.
- **Distribution packaging automation.** Only AUR packaging is maintained
  here; other distributions are external.
- **Configurable audit log path.** `/var/log/voix.log` is intentionally fixed.
- **Full environment preservation for privileged targets.** Intentional for
  package managers and AUR helpers; restricted targets must use `keepenv` or
  `scrub_environment: false`.

---

## 6. Verification gate

Run before every commit on this branch:

```bash
cmake -B build-dbg -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
ninja -C build-dbg -j"$(nproc)"
ctest --test-dir build-dbg --output-on-failure
clang-tidy -p build-dbg src/*.cpp include/*.hpp -- -Iinclude -std=c++26
```

Expected: `121/121` tests pass, `ctest` green, and `clang-tidy` reports no
warnings. The integration tests run unprivileged by passing `geteuid()` as the
trusted executable owner; they do not cover PAM or the real setuid transition
(see §3).
