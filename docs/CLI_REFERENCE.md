# CLI Reference

Usage: `voix [options] <incantation> [args...]`

## Options

- `-h`: Show the help message.
- `-v`: Show version information.
- `-u USER`: Execute as the specified target user (default: root).
- `-C FILE`: Use the specified file as the configuration source (default: `/etc/voix.conf`).
- `-n`: Non-interactive mode; fail if authentication is required.
- `-s`: Execute the user's shell (ascend to shell).
- `-i, --login`: Execute the incantation in a login shell environment.
- `-E, --preserve-env`: Preserve the user's environment variables.
- `-l, --list`: List the rites permitted for the user.
- `-c, --check-config`: Validate the configuration file.
