# Configuration Guide

Voix uses YAML for its configuration, creating a structured and mystical environment for privilege management.

## Terminology Glossary

- `rite`: A specific command (incantation) allowed or restricted by a rule.
- `sanctuary`: The temporary working directory or base path where Voix performs its operations.
- `ordain`: An action that grants permission to perform a rite (equivalent to `permit`).
- `shun`: An action that denies permission to perform a rite (equivalent to `deny`).
- `trust`: A boolean setting. If `true`, the user is not required to provide a token of proof (password) for the ascension.

## Configuration File Structure

The configuration file (default: `/etc/voix.conf`) is composed of two main sections:

### `globals`

- `sanctuary`: The sacred path to the temporary directory where Voix performs its rites.
- `path`: Trusted paths to seek out incantations (executables).

Example:

```yaml
globals:
  sanctuary: /tmp
  path:
    - /bin
    - /usr/bin
```

### `rules`

A list of rules that govern who may ascend and how. Each rule must define the following:

- `action`: `permit` (ordain) to allow the action, or `deny` (shun) to block it.
- `identity`: The soul (user) or group (prefixed with `:`) to which the rule applies.
- `trust`: Boolean (`true` or `false`). If `true`, the ascension is permitted without a token of proof (password).
- `mask`: (Optional) The identity to assume during the rite (defaults to `root`).
- `rite`: (Optional) The specific incantation (full path to the command) being allowed.
- `args`: (Optional) A list of exact arguments that must be present for the rule to match.

Example:

```yaml
rules:
  # Ordain members of the 'admin' group to perform any rite without a token of proof.
  - action: permit
    identity: :admin
    trust: true

  # Shun user 'guest' from running 'rm' with the '-rf' flag.
  - action: deny
    identity: guest
    rite: /bin/rm
    args:
      - -rf
```

For a full example, see [`docs/voix.conf.example`](docs/voix.conf.example).
