# Using Voix as a Functional Alternative to `sudo`/`doas`

This guide explains how to use `voix` as a functional replacement for traditional privilege escalation tools like `sudo` and `doas`. 

While Voix is architected as a Privilege Policy Enforcement Runtime rather than a simple utility, it can be configured to provide a similar user experience to these tools.

## 1. Configuring Voix for Privilege Escalation

Voix manages privileges using configuration rules defined in `/etc/voix.conf`. For detailed information on configuring these rules, refer to [`docs/CONFIG.md`](docs/CONFIG.md).

To grant specific users or groups the ability to escalate privileges, you must define YAML rules in your `/etc/voix.conf`.

## 2. Setting Up a Drop-in Experience

To use `voix` as a functional alternative to `sudo`, you can create an alias in your shell configuration (e.g., `.bashrc` or `.zshrc`):

```bash
alias sudo=voix
```

Alternatively, you can create a symlink in your path:

```bash
sudo ln -s /usr/bin/voix /usr/local/bin/sudo
```

Ensure that the soul or group is configured to be able to use `voix` in `/etc/voix.conf` using the YAML format.

## 3. Supported Flags

Voix includes several flags to support `sudo`-like behavior. See [`docs/CLI.md`](docs/CLI.md) for a full list of options.

Important flags include:

* `-i, --login`: Executes the command in a login shell environment.
* `-E, --preserve-env`: Preserves the user's environment variables.
* `-l, --list`: Lists commands permitted for the current user.

## 4. Limitations

* Ensure that `/etc/voix.conf` is securely configured with restricted permissions (owned by root, not world-writable) to prevent unauthorized modifications to privilege rules.
