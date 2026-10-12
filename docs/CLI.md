# CLI Reference

Usage: `voix [options] <incantation> [args...]`

## Options

| Flag | Long form | Description |
| :--- | :--- | :--- |
| `-h` | `--help` | Show the help message |
| `-v` | `--version` | Show version information |
| `-C FILE` | `--config FILE` | Use the specified file as the configuration source (default: `/etc/voix.conf`). The file must pass the same root-ownership and permission checks as the default configuration. |
| `-c` | `--check-config` | Validate the configuration file |
| `-E` | `--preserve-env` | Request preservation of the user's environment variables. Effective only when the matched rule carries a `keepenv` policy grant; the flag alone cannot widen what the policy allows. |
| `-H` | `--home` | Set `HOME` to the target user's home directory for the executed command. |
| `-i` | `--login` | Execute the incantation in a login shell environment. With a named command the request stays brokered by Voix, so the destructive-command gate still applies (`voix -u root -i cfdisk /dev/sda` is refused). Used bare — `voix -u root -i` — it opens a standalone root shell instead; that requires the target's login shell to be absent from `security.blocklist`, which by default it is not. |
| `-k` | | Invalidate the persisted authentication timestamp for the invoking user (see the `persist` rule option). Works standalone without a command. |
| `-l` | `--list` | List the rites permitted for the current user. Mirrors runtime first-match semantics: a permit whose scope is already denied by an earlier matching deny rule is not listed. |
| `-n` | | Non-interactive mode; fail if authentication is required |
| `-s` | | Execute the user's shell (ascend to shell) |
| `-u USER` | | Execute as the specified target user (default: `root`). Requires an explicit `target` rule in the ACL for non-root users. |
| | `--run-tests` | Run the built-in test suite and exit. Available only in builds configured with testing enabled (`-DBUILD_TESTING=ON`); see ["Testing the Artifact"](../CONTRIBUTING.md#3-testing-the-artifact). |

> [!NOTE]
> The short-only flags `-n`, `-s`, `-u`, and `-k` intentionally have no long
> form, mirroring `doas`/OpenDoas conventions.

## Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | The command ran successfully (or listing/validation succeeded) |
| `1` | Authorization denied, authentication failed, configuration invalid, or a catastrophic command was blocked |
| `127` | The command could not be resolved or executed |
| *other* | The exit status of the executed command is propagated verbatim |
