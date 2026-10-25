# CLI Reference

Usage: `voix [options] <incantation> [args...]`

## Options

| Flag | Long form | Description |
| :--- | :--- | :--- |
| `-h` | `--help` | Show the help message |
| `-v` | `--version` | Show version information |
| `-C FILE` | `--config FILE` | Use the specified file as the configuration source (default: `/etc/voix.conf`). The path must be absolute and every component must be root-owned, free of symlinks, and not group/world writable. The final file is re-checked on the opened descriptor. |
| `-c` | `--check-config` | Validate the configuration file and run semantic policy linting |
| `-E` | `--preserve-env` | Accepted for compatibility but has no effect. Environment preservation is enabled by a `keepenv` rule option or a profile with `scrub_environment: false`; the flag does not add to it. |
| `-H` | `--home` | Set `HOME` to the target user's home directory for the executed command. Without this flag, `HOME` is not set to the target's home; it is present only if it survived sanitization. |
| `-i` | `--login` | Execute via the target's login shell (POSIX `argv[0]` leading-dash convention). Forces `HOME` and `SHELL` to the target's values, even when the rule grants `keepenv` or the target is unconfined. With a named command the request stays brokered by Voix, so the destructive-command gate still applies (`voix -u root -i cfdisk /dev/sda` is refused). Used bare — `voix -u root -i` — it opens an interactive shell as the target, which requires the target's login shell to be absent from `security.blocklist` (the shipped sample blocks `/bin/bash`). |
| `-k` | | Invalidate every persisted authentication ticket belonging to the invoking user. Works standalone without a command. |
| `-l` | `--list` | List the permit rules that apply to the current user. Deny-awareness is limited to an earlier deny with an identical command/args/target scope; a rule without a command is shown as `(all commands)`. This is not a command-by-command prediction. |
| `-n` | | Non-interactive mode. A valid persisted ticket is reused if the matched rule grants `persist`; otherwise Voix fails rather than prompting. `-n` can never trigger a password prompt. |
| `-s` | | Execute the invoking user's shell (`$SHELL`, falling back to the invoking user's passwd shell) as the target. This is not the target's login shell; use `-i` for that. |
| `-u USER` | | Execute as the specified target user (default: `root`). Non-root callers require an explicit `target` rule in the ACL. There is no passwordless-target bypass: the caller must authenticate unless the rule grants `trust`/`nopass`, the caller is root, or a valid `persist` ticket exists. |
| | `--run-tests` | Run the built-in test suite and exit. Available only in builds configured with testing enabled (`-DBUILD_TESTING=ON`); see ["Testing the Artifact"](../CONTRIBUTING.md#3-testing-the-artifact). |

> [!NOTE]
> The short-only flags `-n`, `-s`, `-u`, and `-k` intentionally have no long
> form, mirroring `doas`/OpenDoas conventions.

> [!IMPORTANT]
> Credential verification is skipped only when the invoking user is root, the
> matched rule carries `trust`/`nopass`, or a valid `persist` ticket exists for
> the same caller/target UID pair and the rule carries `persist`. The caller's
> account is validated with `pam_acct_mgmt` on every invocation, including
> skipped-credential paths. The target account is validated separately with its
> own PAM handle; that check is **not** credential verification. Only a
> successful `pam_authenticate()` mints or refreshes a ticket. See
> [`THREATS.md`](../THREATS.md#7-known-limitations).

## Exit Codes

Voix uses stable values based on `sysexits(3)` where an appropriate code
exists. A command's own exit status is propagated verbatim, so the executed
program can also produce any of these values; the table describes what the
value means when Voix returns it itself.

| Code | Name | Meaning |
| :--- | :--- | :--- |
| `0` | success | The command ran successfully, or listing/validation succeeded |
| `1` | failure | Authentication failed or a generic runtime check failed |
| `64` | usage | Invalid command line: unknown flag, missing command, or bad `-u` target |
| `70` | software | Internal invariant failure (fork, waitpid, signal setup) |
| `77` | not-permitted | Policy denied the request, an unsafe executable was refused, or a destructive-command gate blocked it |
| `78` | config | Configuration could not be loaded, parsed, or validated |
| `126` | no-exec | The command was found but could not be executed |
| `127` | not-found | The command could not be found |
| *other* | — | The exit status of the executed command is propagated verbatim |

## Diagnostics and Logging

- User-facing failures are printed as `voix: error: …` followed by an optional
  `voix: hint: …` remediation line. Fatal errors are printed even when
  `core.suppress_stderr` is enabled.
- Audit records go to `/var/log/voix.log` and to `syslog` (facility
  `authpriv`). Each line includes an ISO-8601-style timestamp, level, PID, and
  escaped control characters.
- Security events carry a stable code in brackets after the user, for example
  `[alice] [command.denied] …` or `[alice] [auth.failed] …`. See
  [`include/audit.hpp`](../include/audit.hpp) for the current values; existing
  codes are not renamed.
