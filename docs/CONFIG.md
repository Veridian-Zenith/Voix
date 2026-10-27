# Configuration Guide

Voix uses a structured YAML configuration file to define execution policies.

> [!TIP]
> Validate any policy change before deploying it:
>
> ```bash
> voix -c
> ```
>
> `--check-config` verifies the schema, path permissions **and** runs semantic
> policy linting (empty ACL, unconfined root, redundant rules, open permits,
> missing blocklist).

> [!WARNING]
> Package upgrades never overwrite a live `/etc/voix.conf`. When the file
> already exists, the shipped sample is installed as `/etc/voix.conf.new`
> instead — merge it manually.

## Table of Contents

- [Configuration File Structure](#configuration-file-structure)
  - [`core`](#core)
  - [`acl`](#acl)
  - [`security`](#security)
    - [`profiles` (optional)](#profiles-optional)
    - [`blocklist` (optional)](#blocklist-optional)
  - [Complete Example](#complete-example)

---

## Configuration File Structure

The configuration file (default: `/etc/voix.conf`) is composed of three main sections:

### `core`

- `sanctuary`: Root-owned private directory used for persisted tickets
  (`<sanctuary>/timestamp/`). Use `/var/lib/voix`; do not point this at
  `/tmp` or another world-writable directory. `--check-config` verifies that
  the path is a directory, but not that it or its parents are root-owned and
  non-writable.
- `paths`: Trusted directories for executable resolution. These are used for
  bare command names. Absolute and relative paths supplied by the caller are
  canonicalized and validated (regular file, root-owned, not group/world
  writable) but are not required to live under one of these directories.
- `login_shell`: Whether to default to login shell mode.
- `suppress_stderr`: Whether to suppress stderr log output.
- `unconfined_targets`: List of target usernames that receive the full
  "system" treatment — retained capabilities, no seccomp, no file-descriptor
  scrubbing, and a fully preserved environment (including loader/interpreter
  variables such as `LD_*` and `PYTHON*`). The default is **empty**: no target
  is unconfined unless the configuration says so. Enable one only for a
  specific package-manager workflow. For example, on Arch add `root` and
  `alpm` if you want `voix pacman -Syu` to keep working; on Debian, `root` or
  `_apt`. Prefer an explicit `profile: privileged` rule over making every
  command for that target unconfined.

Example:

```yaml
core:
  sanctuary: /var/lib/voix
  paths:
    - /bin
    - /usr/bin
  unconfined_targets:
    - alpm
```

### `acl`

A mapping of users or groups to rules that govern execution authorization.

- `action`: `permit` to allow the action, or `deny` to block it.
- `options`: List of modifiers for the rule:
    - `trust` or `nopass`: Skip the credential check. Caller account
      validation (`pam_acct_mgmt`) still runs.
    - `keepenv`: Preserve the user's environment variables (minus known
      dangerous loader/interpreter variables). This is the only grant that
      enables environment preservation; the CLI `-E` flag is accepted for
      compatibility but ignored.
    - `persist`: Maintain an authentication timestamp (default TTL: 15
      minutes, stored under `<sanctuary>/timestamp/<caller-uid>-<target-uid>`)
      so subsequent runs can skip the password prompt. Tickets are scoped to
      the caller/target UID pair and are recorded **only** after a successful
      `pam_authenticate()`; trust/nopass/root skips and reused tickets never
      mint or refresh one. `-n` reuses a valid ticket but never prompts.
      Invalidate all of the invoking user's tickets with `voix -k`.
    - `nolog`: Suppress audit-log records containing the command text. An
      outcome-only summary ("execution completed, details withheld") is still
      recorded, and catastrophic-command blocks are always logged in full.
- `env`: (Optional) List of `KEY=VALUE` entries applied to the executed
  command's environment after sanitization. Keys must be valid C identifiers.
- `profile`: (Optional) Name of a security profile to apply (see `security.profiles`). If omitted, Voix uses the `restricted` profile, unless the target is listed in `core.unconfined_targets`, in which case the unconfined "system" profile is applied.
- `target`: (Optional) The user identity to assume during execution (defaults to `root`). Rules without a `target` field only match when executing as root (uid 0). To allow user switching via `-u`, add explicit `target` rules (e.g., `target: postgres`).
- `command`: (Optional) The specific command (full path) being allowed.
- `args`: (Optional) A list of exact arguments that must be present for the rule to match. Supports `*` (any sequence) and `?` (single character) wildcards.

### `security`

#### `profiles` (optional)

Defines named execution profiles that control confinement behavior:

- `retain_full_capabilities`: Preserve all Linux capabilities (`true`) or drop all (`false`). Retaining full capabilities selects the privileged tier, which also skips `PR_SET_NO_NEW_PRIVS` and seccomp.
- `enable_seccomp`: Apply the seccomp syscall blacklist (`true`) or bypass it (`false`). This gates only `blacklist` mode; selecting `allowlist` applies that filter regardless of this setting.
- `enable_resource_limits`: Enforce RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_CORE (`true`) or disable (`false`).
- `scrub_environment`: Reduce the caller's environment to a safe whitelist
  (`true`, default). Set to `false` to keep the caller's environment after the
  dangerous loader/interpreter variables are stripped — the same effect as
  the rule's `keepenv`, granted at profile level. Full verbatim preservation
  is a separate grant (`preserve_full_environment`).
- `preserve_full_environment`: Preserve the entire inherited environment
  verbatim, without stripping loader/interpreter variables (`true`), or apply
  the normal sanitization (`false`). Intended only for unconfined system
  targets.
- `seccomp_mode`: `blacklist` (default: allow everything, kill a fixed set of
  dangerous syscalls) or `allowlist` (default-deny: kill everything except the
  built-in baseline plus `seccomp_allow`). An unrecognized value is a
  configuration error rather than an unfiltered execution.
- `seccomp_allow`: Additional syscall names permitted in `allowlist` mode, on
  top of the baseline (which already covers process startup — including
  `execve`/`execveat` — memory, basic file I/O, signals, timers, polling,
  pipes, and sockets). Unknown names are rejected when the configuration is
  loaded, so `voix --check-config` reports them before any command runs.
  Rejected when `seccomp_mode` is not `allowlist`.

```yaml
security:
  profiles:
    tightly-scoped:
      seccomp_mode: allowlist
      seccomp_allow:
        - mkdir
        - unlink
```

> [!NOTE]
> The allowlist baseline is a starting point, not a complete sandbox for every
> program: a command that mutates the filesystem namespace (`mkdir`,
> `unlink`, `rename`, `chmod`, ...) or creates processes needs those syscalls
> added to `seccomp_allow`. Test a rule with `voix --check-config` and then a
> real invocation before relying on it. See
> [`THREATS.md`](../THREATS.md#5-technical-defenses).

#### `blocklist` (optional)

A list of entries that are globally forbidden, checked before policy
evaluation. Two entry forms are supported:

- **Exact paths** (default): a scalar entry matches the command path exactly,
  e.g. `/bin/sh`.
- **Regex patterns**: prefix an entry with `regex:` to have the remainder
  treated as an ECMAScript regex matched against the full command line
  (command plus arguments, with path-like arguments canonicalized), e.g.
  `regex:^cat /etc/(shadow|sudoers)`. Malformed patterns are rejected at load
  time.

Independent of the blocklist, Voix hardcodes catastrophic-command detection:
`rm -rf` targeting `/` (including globs, double slashes, long options and
cwd-relative paths that resolve to `/`), `dd` writing to raw block devices
(sd/hd/vd/nvme/mmcblk/dm/mapper/disk aliases or the root device), the whole
`mkfs*` family, `mkswap`, and the partition/destruction tools `fdisk`,
`sfdisk`, `cfdisk`, `parted`, `wipe`, `wipefs`, `shred` — matched by basename,
so alternate path prefixes are covered too.

> [!IMPORTANT]
> Catastrophic detection is hardcoded and runs before policy evaluation for
> the command Voix is asked to execute. No `permit` rule, privileged group
> membership, or `seccomp`/`profile:` setting can permit a directly requested
> blocked tool. The gate does not inspect commands launched by a permitted
> shell or interpreter, so a shell can still invoke these tools. For direct
> Voix requests, running them requires a shell already authenticated as root
> — TTY login, `su -`, or bare `-i`. See
> [`docs/SUDO.md`](SUDO.md#3-destructive-operations-require-a-direct-root-login).

> [!NOTE]
> Exact-path blocklist entries are canonicalized before comparison. An entry
> of `/bin/sh` also blocks `/usr/bin/sh` on merged-`/usr` systems and rejects
> alternate spellings such as `/bin/../bin/sh`. The final path component is
> preserved so multicall applets remain distinct: `/usr/bin/ls` does not
> block `/usr/bin/cat`. Use a `regex:` entry when the intent is to match a
> tool by arguments or a broader path pattern.

Example:

```yaml
security:
  profiles:
    restricted:
      retain_full_capabilities: false
      enable_seccomp: true
      enable_resource_limits: true
      scrub_environment: true
    privileged:
      retain_full_capabilities: true
      enable_seccomp: false
      enable_resource_limits: false
      scrub_environment: false
      preserve_full_environment: false
  blocklist:
    - /bin/sh
```

### Complete Example

<details>
<summary>Full annotated example (click to expand)</summary>

```yaml
core:
  sanctuary: /var/lib/voix
  paths:
    - /bin
    - /usr/bin
  unconfined_targets: []

acl:
  group:
    wheel:
      - action: permit
        command: /usr/bin/systemctl
        args: [restart, nginx]
  user:
    admin:
      - action: permit
        options: [persist]
        target: deploy
        command: /usr/bin/systemctl
        args: [restart, myapp]

security:
  profiles:
    restricted:
      retain_full_capabilities: false
      enable_seccomp: true
      enable_resource_limits: true
      scrub_environment: true
    privileged:
      retain_full_capabilities: true
      enable_seccomp: false
      enable_resource_limits: false
      scrub_environment: false
      preserve_full_environment: false
  blocklist:
    - /bin/sh
    - /bin/bash
    - /usr/bin/env
```

</details>

For the canonical example, see [`config/voix.conf`](../config/voix.conf).
