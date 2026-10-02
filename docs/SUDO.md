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

## 3. Destructive Operations Require a Direct Root Login

Voix refuses disk and partition rites unconditionally. This check is
independent of your ACL — it runs before policy evaluation, so no `permit`
rule, no membership in `wheel`, and no `-n` flag can bypass it:

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

This is a deliberate confirmation gate. A passwordless `sudo` on a shared
workstation should not be able to rewrite a partition table. To perform
these operations, authenticate as root by a means that cannot be automated
into a policy exception:

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

## 4. Granting Service Accounts Their Own Rites

Because the destructive gate is unconditional, day-to-day service
administration happens through the ACL instead. Each rule that omits
`target:` matches only uid 0; add an explicit `target:` to grant a
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
> The blocklist is matched by exact path. A shell entry such as
> `/bin/sh` catches `/bin/sh` but not `/usr/bin/./bash`. Where the intent
> is "no interactive shells at all", write `regex:` entries instead
> (see [`docs/CONFIG.md`](CONFIG.md#blocklist-optional)) or rely on the
> `-i` login-shell form above.

## 5. Supported Flags

Voix includes several flags to support `sudo`-like behavior. See [`docs/CLI.md`](CLI.md) for a full list of options.

Important flags include:

* `-i, --login`: Executes the command in a login shell environment. Named commands stay brokered by Voix (`sudo -u root -i cfdisk /dev/sda` is still refused); used bare it opens a standalone root shell — see section 3.
* `-E, --preserve-env`: Requests preservation of the user's environment variables. Effective only when the matched rule carries a `keepenv` policy grant.
* `-l, --list`: Lists commands permitted for the current user (deny-aware, mirroring runtime first-match semantics).
* `-k`: Invalidates the persisted authentication timestamp for the invoking user.
* `-n`: Non-interactive mode; fails instead of prompting for authentication.

## 6. Limitations

* Ensure that `/etc/voix.conf` is securely configured with restricted permissions (owned by root, not world-writable) to prevent unauthorized modifications to privilege rules.
* Destructive disk and partition operations cannot be granted through policy at all; see section 3.
