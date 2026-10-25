# CLI Reference

Usage: `voix [options] <incantation> [args...]`

## Options

| Flag | Long form | Description |
| :--- | :--- | :--- |
| `-h` | `--help` | Show the help message |
| `-v` | `--version` | Show version information |
| `-C FILE` | `--config FILE` | Use the specified file as the configuration source (default: `/etc/voix.conf`). The file must be a regular root-owned file with no group/world write bits. Parent-directory ownership is not checked. |
| `-c` | `--check-config` | Validate the configuration file |
| `-E` | `--preserve-env` | Accepted for compatibility but has no effect. Environment preservation is enabled by a `keepenv` rule option; the flag does not add to it. |
| `-H` | `--home` | Set `HOME` to the target user's home directory for the executed command. Without this flag, `HOME` is not set to the target's home; it is present only if it survived sanitization. |
| `-i` | `--login` | Execute via the target's login shell (POSIX `argv[0]` leading-dash convention). With a named command the request stays brokered by Voix, so the destructive-command gate still applies (`voix -u root -i cfdisk /dev/sda` is refused); a permitted shell named as the command is not inspected further. Used bare — `voix -u root -i` — it opens an interactive shell as the target, which requires the target's login shell to be absent from `security.blocklist` (by default it is not). `-i` does **not** set `HOME` to the target's home; use `-H`. With `keepenv` (or an unconfined target) the caller's `HOME` can survive, and the login shell may read caller-owned startup files as the target. |
| `-k` | | Invalidate the persisted authentication timestamp for the invoking user (see the `persist` rule option). Works standalone without a command. |
| `-l` | `--list` | List the permit rules that apply to the current user. Deny-awareness is limited to an earlier deny with an identical command/args/target scope; a rule without a command is shown as `(all commands)`. This is not a command-by-command prediction. |
| `-n` | | Non-interactive mode; fail if a credential check would be required. Persisted tickets are not consulted under `-n`. |
| `-s` | | Execute the invoking user's shell (`$SHELL`, falling back to the invoking user's passwd shell) as the target. This is not the target's login shell; use `-i` for that. |
| `-u USER` | | Execute as the specified target user (default: `root`). Requires an explicit `target` rule in the ACL for non-root users. A target account with no usable password currently skips the credential check (see below). |
| | `--run-tests` | Run the built-in test suite and exit. Available only in builds configured with testing enabled (`-DBUILD_TESTING=ON`); see ["Testing the Artifact"](../CONTRIBUTING.md#3-testing-the-artifact). |

> [!NOTE]
> The short-only flags `-n`, `-s`, `-u`, and `-k` intentionally have no long
> form, mirroring `doas`/OpenDoas conventions.

> [!WARNING]
> Credential verification is skipped when the invoking user is root, the
> matched rule carries `trust`/`nopass`, the target account has no usable
> password, or a valid `persist` ticket exists and the rule carries `persist`
> (not under `-n`). `pam_acct_mgmt` validates the invoking user's account,
> not the target's. See
> [`THREATS.md`](../THREATS.md#7-known-limitations).

## Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | The command ran successfully (or listing/validation succeeded) |
| `1` | Authorization denied, authentication failed, configuration invalid, or a catastrophic command was blocked |
| `127` | The command could not be resolved or executed |
| *other* | The exit status of the executed command is propagated verbatim |
