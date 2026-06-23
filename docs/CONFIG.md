# Configuration Guide

Voix uses a structured YAML configuration file to define execution policies.

## Configuration File Structure

The configuration file (default: `/etc/voix.conf`) is composed of three main sections:

### `core`

- `sanctuary`: Temporary working directory path.
- `paths`: Trusted directories for executable resolution.
- `login_shell`: Whether to default to login shell mode.
- `suppress_stderr`: Whether to suppress stderr log output.
- `privileged_users`: List of usernames treated as privileged (defaults to `["root", "alpm"]`).

Example:

```yaml
core:
  sanctuary: /tmp
  paths:
    - /bin
    - /usr/bin
  privileged_users:
    - root
    - alpm
```

### `acl`

A mapping of users or groups to rules that govern execution authorization.

- `action`: `permit` to allow the action, or `deny` to block it.
- `options`: List of modifiers for the rule:
    - `trust` or `nopass`: Allow execution without authentication.
    - `keepenv`: Preserve the user's environment variables.
    - `persist`: Maintain a session to avoid repeated authentication.
    - `nolog`: Suppress logging of this execution.
- `profile`: (Optional) Name of a security profile to apply (see `security.profiles`). If omitted, Voix selects automatically based on target user.
- `target`: (Optional) The user identity to assume during execution (defaults to `root`).
- `command`: (Optional) The specific command (full path) being allowed.
- `args`: (Optional) A list of exact arguments that must be present for the rule to match. Supports `*` (any sequence) and `?` (single character) wildcards.

### `security`

#### `profiles` (optional)

Defines named execution profiles that control confinement behavior:

- `retain_full_capabilities`: Preserve all Linux capabilities (`true`) or drop all (`false`).
- `enable_seccomp`: Apply seccomp syscall blacklist (`true`) or bypass (`false`).
- `enable_resource_limits`: Enforce RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_CORE (`true`) or disable (`false`).
- `scrub_environment`: Clear and restrict environment variables (`true`) or preserve (`false`).

#### `blocklist` (optional)

A list of commands and regex patterns that are globally forbidden.

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
  blocklist:
    - /bin/sh
```

### Complete Example

```yaml
core:
  sanctuary: /tmp
  paths:
    - /bin
    - /usr/bin
  privileged_users:
    - root
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
  blocklist:
    - /bin/sh
```

For the canonical example, see [`config/voix.conf`](config/voix.conf).
