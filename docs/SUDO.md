# Using Voix in `sudo`/`doas` Workflows

This guide explains how to use `voix` in workflows that resemble traditional privilege escalation tools like `sudo` and `doas`.

Voix is architected as a Privilege Policy Enforcement Runtime rather than a simple utility. It can provide a familiar user experience, but it is **not** a drop-in replacement and does not implement the full `sudo`/`doas` command-line surface. The `provides`/`conflicts` entries in the AUR packages exist for dependency resolution, not as a claim of CLI equivalence.

## Table of Contents

- [1. Configuring Voix for Privilege Escalation](#1-configuring-voix-for-privilege-escalation)
- [2. Alias-Based Compatibility](#2-alias-based-compatibility)
- [3. Destructive Operations Require a Direct Root Login](#3-destructive-operations-require-a-direct-root-login)
- [4. Granting Service Accounts Their Own Rites](#4-granting-service-accounts-their-own-rites)
- [5. Supported Flags](#5-supported-flags)
- [6. Limitations](#6-limitations)

---

## 1. Configuring Voix for Privilege Escalation

Voix manages privileges using configuration rules defined in `/etc/voix.conf`. For detailed information on configuring these rules, refer to [`CONFIG.md`](CONFIG.md).

To grant specific users or groups the ability to escalate privileges, you must define YAML rules in your `/etc/voix.conf`.

## 2. Alias-Based Compatibility

For operational familiarity, you can create an alias in your shell configuration (e.g., `.bashrc` or `.zshrc`):

```bash
alias sudo=voix
```

Alternatively, you can create a symlink in your path:

```bash
sudo ln -s /usr/bin/voix /usr/local/bin/sudo
```

These are convenience measures, not compatibility guarantees. Scripts that rely on `sudo`-specific options, environment handling, or exit semantics may break, and the AUR packages already declare `provides`/`conflicts` for `sudo` and `doas`. Ensure that the user or group is configured to use `voix` in `/etc/voix.conf` using the YAML format.

## 3. Destructive Operations Require a Direct Root Login

Voix refuses directly requested disk and partition rites. This check is
independent of your ACL — it runs before policy evaluation, so no `permit`
rule, no membership in `wheel`, and no `-n` flag can bypass it. It inspects
the command Voix is asked to execute; a permitted shell or interpreter can
still invoke these tools. In the examples below, `sudo` means `voix` (via an
alias or symlink).

| Refused | Tools |
| :--- | :--- |
| Partitioning | `fdisk`, `sfdisk`, `cfdisk`, `parted` |
| Erasing | `wipe`, `wipefs`, `shred` |
| Filesystem creation | `mkswap`, the entire `mkfs*` family |
| Raw device writes | `dd` targeting a block device or the root device |
| Root removal | `rm -rf /` and its equivalent spellings |

```
  $ sudo cfdisk /dev/nvme0n1
  voix: command blocked: catastrophic command forbidden.
```

This is a deliberate confirmation gate. A passwordless rule on a shared
workstation should not be able to rewrite a partition table as a directly
requested Voix command. To perform these operations, use a shell already
running as root by a means that cannot be automated into a policy exception:

* TTY login as `root`
* `su -`
* `sudo -u root -i`

That last form is worth understanding, because `-i` behaves in two
distinct ways depending on whether you name a command:

```
  $ sudo -u root -i lsblk      # runs lsblk as root, then exits
  NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
  sda           8:0    0 476,9G  0 disk

  $ sudo -u root -i            # no command: opens a standalone root shell
  [root@host ~]# whoami
  root
  [root@host ~]# exit
```

The named-command form is brokered by Voix, so the destructive gate still
applies to whatever you name:

```
  $ sudo -u root -i lsblk              # allowed - lsblk is harmless
  $ sudo -u root -i cfdisk /dev/sda    # BLOCKED - cfdisk is refused
  voix: command blocked: catastrophic command forbidden.
```

The bare form opens a shell and simply waits. Once you are inside it,
Voix is no longer in the request path, so the destructive tools are
ordinary commands typed at the prompt:

```
  $ sudo -u root -i
  [root@host ~]# cfdisk /dev/sda       # not a Voix request - it just runs
```

> [!IMPORTANT]
> The bare form requires that the target's login shell is **not** in your
> `security.blocklist`. Voix resolves a bare `-i` to that shell's path
> from `/etc/passwd` and applies the blocklist to it — root's is
> `/bin/bash`. The shipped `config/voix.conf` blocklists `/bin/bash`, so
> on a default install `voix -u root -i` is refused. Remove that entry to
> enable the standalone shell:
>
> ```yaml
> security:
>   blocklist:
>     - /bin/sh
>     - /bin/dash
>     # /bin/bash removed so `voix -u root -i` can open a root shell
> ```
>
> With `/bin/bash` removed, `-i` with a command still works exactly as
> before and the destructive gate is unchanged — `voix -u root -i cfdisk
> /dev/sda` stays blocked. Only the bare form depends on this.

> [!NOTE]
> `-i` forces `HOME` and `SHELL` to the target's values, even when the rule
> grants `keepenv` or the target is unconfined. This prevents a login shell
> from reading caller-owned startup files as the target. `-H` applies the
> same `HOME` override to non-login commands.

## 4. Granting Service Accounts Their Own Rites

Because the destructive gate applies to directly requested commands,
day-to-day service administration happens through the ACL instead. Each rule
that omits `target:` matches only uid 0; add an explicit `target:` to grant a
non-root identity:

```yaml
acl:
  group:
    wheel:
      # As root: every rite not otherwise blocked.
      - action: permit
        options: [trust, keepenv]

      # As a specific service account: only these identities.
      - action: permit
        options: [trust]
        target: searxng

      - action: permit
        options: [trust]
        target: postgres

  user:
    root:
      - action: permit
        options: [trust, keepenv]
```

With the above, a `wheel` member can restart searxng as the `searxng`
user, but a rule targeting `searxng` does not grant them anything as
root. Validate any edit before relying on it:

```
  $ sudo -c
  Configuration is valid.
```

`sudo -c` also runs the policy analyzer, which flags open permits,
redundant rules, and an empty ACL.

> [!NOTE]
> Exact-path blocklist entries are canonicalized before comparison, so
> `/bin/sh` also blocks `/usr/bin/sh` on merged-`/usr` systems and alternate
> spellings such as `/usr/bin/./bash`. The final component is preserved so
> multicall applets stay distinct. Use `regex:` entries for broader patterns
> (see [`CONFIG.md`](CONFIG.md#blocklist-optional)). The `-i` login-shell
> form is not a substitute for a blocklist entry: the shell must be absent
> from the blocklist for the bare form to run.

## 5. Supported Flags

Voix includes several flags to support `sudo`-like behavior. See [`CLI.md`](CLI.md) for a full list of options.

Important flags include:

* `-i, --login`: Runs the command via the target's login shell. Named commands stay brokered by Voix (`sudo -u root -i cfdisk /dev/sda` is still refused); used bare it opens an interactive shell as the target — see section 3. Forces `HOME` and `SHELL` to the target's values.
* `-E, --preserve-env`: Accepted for compatibility but has no effect. Environment preservation is enabled by a `keepenv` rule.
* `-l, --list`: Lists permit rules for the current user. Deny-awareness is limited to an earlier deny with an identical command/args/target scope.
* `-k`: Invalidates all persisted authentication tickets for the invoking user.
* `-n`: Non-interactive mode; reuses a valid persisted ticket if the rule grants `persist`, otherwise fails instead of prompting.

## 6. Limitations

* Ensure that `/etc/voix.conf` is securely configured with restricted permissions (owned by root, not world-writable) to prevent unauthorized modifications to privilege rules. `-C` additionally rejects paths with any untrusted component.
* The shipped sample is closed by default: no user or group is trusted, no target is unconfined, and the ACL contains no permits. Add only the rules you need and validate with `voix --check-config`.
* Destructive disk and partition operations cannot be granted as a directly requested Voix command; a permitted shell can still run them. See section 3.
* Every requested command — bare name, relative path, or absolute path — is canonicalized and must resolve to a regular root-owned executable without group/world write permission. The validated inode is pinned and executed with `fexecve(2)`.
* `-i` forces `HOME`/`SHELL` to the target; `-H` does the same for `HOME` on non-login commands.
* `-E` is accepted but ignored; `keepenv` alone controls environment preservation.
* `-s` runs the invoking user's shell, not the target's login shell.
* There is no passwordless-target bypass: the caller must authenticate unless the rule grants `trust`/`nopass`, the caller is root, or a valid persisted ticket exists.
