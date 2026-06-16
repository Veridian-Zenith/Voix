# Configuration Guide

Voix uses YAML for its configuration, creating a structured and mystical environment for privilege management.

## Terminology Glossary

- `rite`: A specific command (incantation) allowed or restricted by a rule.
- `sanctuary`: The temporary working directory or base path where Voix performs its operations.
- `permit`: An action that grants permission to perform a rite.
- `deny`: An action that denies permission to perform a rite.
- `options`: Modifiers that alter the nature of the ascension (e.g., `trust`, `keepenv`).
- `pattern`: When used in `args`, allows for flexible matching using variables.

## Configuration File Structure

The configuration file (default: `/etc/voix.conf`) is composed of two main sections:

### `core`

- `sanctuary`: The sacred path to the temporary directory where Voix performs its rites.
- `paths`: Trusted paths to seek out incantations (executables).

Example:

```yaml
core:
  sanctuary: /tmp
  paths:
    - /bin
    - /usr/bin
```

### `acl`

A mapping of users or groups to rules that govern who may ascend and how.

- `action`: `permit` to allow the action, or `deny` to block it.
- `options`: List of modifiers for the rule:
    - `trust`: Allow ascension without a token of proof (password).
    - `keepenv`: Preserve the user's environment variables.
    - `persist`: Maintain a session to avoid repeated authentication.
    - `nolog`: Suppress the logging of this rite.
- `target`: (Optional) The identity to assume during the rite (defaults to `root`).
- `command`: (Optional) The specific incantation (full path to the command) being allowed.
- `args`: (Optional) A list of exact arguments that must be present for the rule to match.

Example:

```yaml
acl:
  group:
    # Ordain members of the 'wheel' group to perform any rite with ritual trust.
    wheel:
      - action: permit
        options: [trust]

  user:
    # Shun user 'guest' from running 'rm' with the '-rf' flag.
    guest:
      - action: deny
        command: /bin/rm
        args: [ -rf ]
```

For a full example, see [`docs/voix.conf.example`](docs/voix.conf.example).
