# CLI Reference

Usage: `voix [options] <incantation> [args...]`

## Options

- `-h, --help`: Show the help message.
- `-v, --version`: Show version information.
- `-u USER`: Execute as the specified target user (default: root). Requires an explicit `target` rule in the ACL for non-root users.
- `-C FILE`, `--config FILE`: Use the specified file as the configuration source (default: `/etc/voix.conf`). The file must pass the same root-ownership and permission checks as the default configuration.
- `-n`: Non-interactive mode; fail if authentication is required.
- `-s`: Execute the user's shell (ascend to shell).
- `-i, --login`: Execute the incantation in a login shell environment.
- `-E, --preserve-env`: Request preservation of the user's environment variables. Effective only when the matched rule carries a `keepenv` policy grant; the flag alone cannot widen what the policy allows.
- `-l, --list`: List the rites permitted for the current user. Mirrors runtime first-match semantics: a permit whose scope is already denied by an earlier matching deny rule is not listed.
- `-c, --check-config`: Validate the configuration file.
- `-k`: Invalidate the persisted authentication timestamp for the invoking user (see the `persist` rule option). Works standalone without a command.

## Exit Codes

- `0`: The command ran successfully (or listing/validation succeeded).
- `1`: Authorization denied, authentication failed, configuration invalid, or a catastrophic command was blocked.
- `127`: The command could not be resolved or executed.
- Otherwise: the exit status of the executed command is propagated verbatim.
