# Voix TODO

Living tracker for the security-hardening branch and the work that follows it.
Update this file whenever an item's state changes, and record every
user-visible change in [`CHANGELOG.md`](CHANGELOG.md).

| Field | Value |
| :--- | :--- |
| **Branch** | `master` (released) |
| **Base** | `origin/master` at `da0ea5c` (merge of PR #33) |
| **Release** | `4.14.0` (2026-10-27; `4.13.3` was the previous release) |
| **Status** | Release prepared; post-merge CI green and no open CodeQL alerts |
| **Last updated** | 2026-10-27 |

Legend: `[ ]` open · `[~]` in progress · `[x]` done · `[>]` deferred by design

---

## 1. Merge checklist

- [x] Open a pull request for `security/p0-hardening` against `master`.
  PR [#33](https://github.com/Veridian-Zenith/Voix/pull/33) was merged as
  `da0ea5c`.
- [x] Confirm CI is green on the branch: `Test Suite`, `CodeQL Analysis`, and
  the repository's CodeQL default setup.
- [x] Re-run the local gate from a clean build directory (see
  [§6](#6-verification-gate)).
- [x] Run `clang-tidy` over `src/*.cpp include/*.hpp`; keep it warning-free.
- [x] Dependabot PR #32 (`github/codeql-action` 4.38.3 → 4.39.1) is merged
  into `master`. `origin/master` is merged into this branch as `5d02461`, and
  the conflict in `.github/workflows/codeql.yml` was resolved in favour of
  `4.39.1`.
- [x] Re-check the CodeQL "Uncontrolled process operation" alert after the
  branch lands. Both `execv` call sites from `master` are now `fexecve` on a
  pinned, inode-verified descriptor; no open alerts remain.
- [x] Decide the release vehicle: `4.14.0`, because the policy defaults and
  exit codes are breaking. `4.14.0-beta.1` was the development marker and is
  not a release tag.
- [x] Update the source version, manpage date, and release notes for `4.14.0`.
- [ ] After the `v4.14.0` artifacts are published, update
  `pkg/voix/PKGBUILD` and `pkg/voix-bin/PKGBUILD` (`pkgver=4.14.0`,
  `pkgrel=1`, new checksums) and push them to the AUR. AUR `pkgver` cannot
  contain `-`; the stable version has no suffix.
- [x] Confirm the shipped `config/voix.conf` remains closed by default and
  document the migration for existing operators: empty ACL, no implicit
  `wheel` trust, no unconfined targets, `/var/lib/voix` sanctuary, and the new
  `sysexits(3)` exit codes.

---

## 2. P1 — completed follow-ups

- [x] **2.1 `-s` uses the target account's login shell.** `-s` and bare `-i`
  now resolve the target's passwd shell through
  `resolve_login_shell()` (`src/system_utils.cpp`) with `/bin/sh` as the
  fallback. The caller's `$SHELL` is never consulted, so a caller cannot
  influence the executed binary. Unit coverage asserts that `$SHELL` is
  ignored and that unknown accounts fall back safely; the executed shell is
  still subject to the root-owned/non-writable executable check. `-s` and
  bare `-i` share one branch. See `docs/CLI.md` and `THREATS.md` §7.
- [x] **2.2 Sanctuary ownership and parent-chain validation.**
  `FileUtils::is_trusted_config_path()` was generalized to
  `FileUtils::is_trusted_path()`, and `Config::validate_sanctuary_path()` now
  requires the sanctuary to exist, be a directory, and have every component
  root-owned, non-group/world-writable, and free of symlinks. Secure loads
  (`Config::load(..., true)`, used by production and `--check-config`)
  enforce it before any ticket is read or written; insecure test loads keep
  working. Regression tests cover `/tmp`, relative, missing, empty, `/`, and
  the installed `/var/lib/voix` sanctuary.
- [x] **2.3 `-l` deny-awareness.** `PermissionChecker::list_permitted_entries()`
  evaluates permits against the same ordered rules as execution. A deny that
  fully covers a permit suppresses it; a partial cover marks the entry
  `conditional`, rendered by `voix -l` as
  `(partially restricted by an earlier deny)`. `list_permitted_rules()` stays
  as a compatibility wrapper. Tests cover broader denies, partial/pattern
  denies, a deny for another target, a deny after a permit, and the original
  exact-scope behavior.

---

## 3. P2 — follow-up hardening

- [ ] **Pin the executable at resolution time.** `resolve_executable()` records
  a `(dev, ino)` pair and `Command::execute` opens the path after
  authentication. A root-owned replacement could in principle recycle the
  inode before that open. Carry the validated descriptor (or a stronger
  identity such as `ctime`/`size`) from resolution through execution. Impact
  is low because replacing a root-owned executable requires root or a
  writable non-sticky root-owned directory.
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

## 4. Completed in 4.14.0 (P0)

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

### `e8d93c7` / `5d02461` — dependabot sync

- `github/codeql-action` 4.38.3 → 4.39.1. The earlier cherry-pick (`e8d93c7`)
  carried 4.39.0; `origin/master` now includes PR #32 with 4.39.1, merged
  into this branch as `5d02461` with the workflow conflict resolved to
  `4.39.1`.

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

Run before every commit:

```bash
cmake -B build-dbg -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
ninja -C build-dbg -j"$(nproc)"
ctest --test-dir build-dbg --output-on-failure
clang-tidy -p build-dbg src/*.cpp include/*.hpp -- -Iinclude -std=c++26
```

Expected: `134/134` tests pass, `ctest` green, and `clang-tidy` reports no
warnings. The integration tests run unprivileged by passing `geteuid()` as the
trusted executable owner; they do not cover PAM or the real setuid transition
(see §3).
