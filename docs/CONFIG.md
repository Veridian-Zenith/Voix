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

## Configuration File Structure

The configuration file (default: `/etc/voix.conf`) is composed of three main sections:

### `core`

- `sanctuary`: Temporary working directory path.
- `paths`: Trusted directories for executable resolution.
- `login_shell`: Whether to default to login shell mode.
- `suppress_stderr`: Whether to suppress stderr log output.
- `unconfined_targets`: List of target usernames that receive the full
  "system" treatment — retained capabilities, no seccomp, no file-descriptor
  scrubbing, and a fully preserved environment (including loader/interpreter
  variables such as `LD_*` and `PYTHON*`). This is required for package
  managers: `root` runs `pacman` and must `chown` its download directories
  (needs `CAP_CHOWN`), while `alpm` is its internal unprivileged drop-user
  that also needs the full environment for AUR helpers. Defaults to
  `["root", "alpm"]`. Remove `root` to confine generic root commands (then
  grant the package manager explicitly via a rule with `profile: privileged`).
  For other distributions, set the equivalent package-manager target here
  (for example `root` for `apt`/`dnf`, or `_apt` on Debian).

Example:

```yaml
core:
  sanctuary: /tmp
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
    - `trust` or `nopass`: Allow execution without authentication.
    - `keepenv`: Preserve the user's environment variables (minus known
      dangerous loader/interpreter variables). The CLI `-E` flag can only
      request what a `keepenv` policy grant already allows.
    - `persist`: Maintain an authentication timestamp (default TTL: 15
      minutes, stored under `<sanctuary>/timestamp/`) so subsequent runs skip
      the password prompt. Account validation still runs every time.
      Invalidate with `voix -k`.
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

- `retain_full_capabilities`: Preserve all Linux capabilities (`true`) or drop all (`false`).
- `enable_seccomp`: Apply seccomp syscall blacklist (`true`) or bypass (`false`).
- `enable_resource_limits`: Enforce RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_CORE (`true`) or disable (`false`).
- `scrub_environment`: Clear and restrict environment variables (`true`) or preserve (`false`).
- `preserve_full_environment`: Preserve the entire inherited environment
  verbatim, without stripping loader/interpreter variables (`true`), or apply
  the normal sanitization (`false`). Intended only for unconfined system
  targets.

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
  sanctuary: /tmp
  paths:
    - /bin
    - /usr/bin
  unconfined_targets:
    - alpm

acl:
  group:
    wheel:
      - action: permit
        options: [trust, keepenv]
        profile: restricted
  user:
    admin:
      - action: permit
        options: [trust]
        profile: privileged

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

</details>

For the canonical example, see [`config/voix.conf`](config/voix.conf).
