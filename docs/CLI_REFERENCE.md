# CLI Reference

Usage: `voix [options] <incantation> [args...]`

## Options

- `-h, --help`: Show the help message.
- `-v, --version`: Show version information.
- `-u, --user USER`: Execute as the specified target user (default: root).
- `-C, --config FILE`: Use the specified file as the configuration source (default: `/etc/voix.conf`).
- `-n, --non-interactive`: Non-interactive mode; fail if authentication is required.
- `-s, --shell`: Execute the user's login shell (ascend to shell).
- `-i, --login`: Execute the incantation in a login shell environment.
- `-E, --preserve-env`: Preserve the user's environment variables.
- `-l, --list`: List the rites permitted for the user.
