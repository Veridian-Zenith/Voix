# Using Voix as a `sudo` Replacement

This guide explains how to configure `voix` as a drop-in replacement for `sudo` to manage privilege escalation.

## 1. Configuring Voix for Privilege Escalation

Voix manages privileges using configuration rules defined in `/etc/voix.conf`. For detailed information on configuring these rules, refer to [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md).

To grant specific users or groups the ability to escalate privileges, you must define YAML rules in your `/etc/voix.conf`.

## 2. Setting Up a Drop-in Experience

To use `voix` as a `sudo` replacement, you can create an alias in your shell configuration (e.g., `.bashrc` or `.zshrc`):

```bash
alias sudo=voix
```

Alternatively, you can create a symlink in your path:

```bash
sudo ln -s /usr/bin/voix /usr/local/bin/sudo
```

Ensure that the soul or group is configured to be able to use `voix` in `/etc/voix.conf` using the YAML format.

## 3. Supported Flags

Voix includes several flags to support `sudo`-like behavior. See [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md) for a full list of options.

Important flags include:

* `-i, --login`: Executes the incantation in a login shell environment.
* `-E, --preserve-env`: Preserves the user's environment variables.
* `-l, --list`: Lists the rites permitted for the user (pending full implementation).

## 4. Limitations

* The `-l` (`--list`) flag is currently a placeholder and does not yet list permitted rites as expected.
* Ensure that `/etc/voix.conf` is securely configured with restricted permissions (owned by root, not world-writable) to prevent unauthorized modifications to privilege rules.
