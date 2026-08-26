# Threat Model and Security Architecture

Voix is a Privilege Policy Enforcement Runtime designed to supersede traditional privilege escalation tools with a more transparent, minimal, and strictly controlled security model. This document outlines the attack surface, the threat model, and the technical mitigations implemented to ensure system integrity.

> [!IMPORTANT]
> Every claim in this document is backed by code reachable from the
> execution path and exercised by the unit-test suite (`tests/`, 84 tests)
> or by the runtime hardening matrix documented in [`docs/TESTING.md`](docs/TESTING.md).

## 1. Trusted Computing Base

To ensure transparency and auditability, Voix maintains a minimal TCB. Unlike traditional tools that have grown complex over decades, Voix is designed for a narrow, high-assurance scope.

| Metric | Traditional Tools (approx.) | Voix | Note |
| :--- | :--- | :--- | :--- |
| **Lines of Code** | ~180,000 | **~3,770** (`src/` + `include/`, 2,638 impl + 1,136 headers) | ~48x smaller attack surface |
| **Test Suite** | varies | ~1,810 lines, 84 tests incl. adversarial cases | Ships with the repo |
| **External Dependencies** | Many (varies) | 2 required, 2 optional | `yaml-cpp`, `pam` (required); `libcap`, `libseccomp` (optional) |
| **Binary Size (Release)** | ~1.2 MB | **~552 KB** (stripped, ThinLTO) | Clang `-O3` + ICF + `--strip-all` |
| **Config Language** | Sudoers (custom) | YAML (standard) | Reduced parsing complexity |
| **CVE History** | Extensive | 0 | New design eliminates legacy bugs |

<details>
<summary>How these numbers are produced</summary>

```bash
# Source lines (implementation + headers, excluding tests)
wc -l src/*.cpp include/*.hpp | tail -1

# Test suite size
wc -l tests/*.cpp tests/*.hpp | tail -1

# Stripped release binary size
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build
ls -la build/voix
```

</details>

## 2. Threat Model

The primary threat actor is a **local authenticated user** attempting to gain unauthorized root privileges or execute privileged operations beyond their assigned scope.

### Attack Vectors

| Vector | Primary Mitigation | Defense-in-Depth |
| :--- | :--- | :--- |
| Configuration tampering | Root ownership + `O_NOFOLLOW` fd-based read | Symlink rejection, group/world write-bit rejection, parent-dir trust |
| Binary exploitation | Hardened build (PIE, RELRO, CET, stack-protector) | Minimal TCB, modern C++26 toolchain |
| Authentication bypass | Strict PAM lifecycle; `acct_mgmt` always runs | Echo-controlled conversation, zeroed buffers |
| Command injection | `execv()` (no shell), environment sanitization | Catastrophic-command detection, blocklist |
| Kernel exploitation | seccomp blacklist for non-privileged targets | Unconditional `PR_SET_NO_NEW_PRIVS` below privileged tier |
| Signal-based attacks | `pthread_sigmask(SIG_BLOCK)` around `fork()` | Child resets all handlers to `SIG_DFL` |
| Audit-log forgery | Control-character escaping in log writer | Symlink-resistant `O_NOFOLLOW\|O_APPEND` opens |
| Timestamp-ticket tampering | Owner/mode verified on open fd, future timestamps rejected | Tickets live in a root-only `0700` directory |

## 3. Attack Surface Analysis

### The Configuration File (`/etc/voix.conf`)
The configuration file defines the entire security policy. If a user can write to this file, they effectively own the system.

- **Risk**: YAML parsing vulnerabilities in `yaml-cpp`; unauthorized modification; symlink swaps.
- **Mitigation**:
    - **Strict Ownership**: root-owned file *and* effective-UID check performed on the opened descriptor.
    - **Strict Permissions**: group- and world-writable files are rejected.
    - **TOCTOU-Safe Read**: `open(O_NOFOLLOW)` + `fstat()` verification + single-fd read loop — the parsed bytes provably come from the verified inode.

> [!WARNING]
> Upgrades never overwrite a live configuration: the installer writes
> `/etc/voix.conf.new` instead and leaves the administrator's policy intact.

### The Setuid Binary
To transition from a standard user to root, Voix must be installed as setuid root.

- **Risk**: Memory-safety issues (buffer overflows, use-after-free) in C++ code.
- **Mitigation**:
    - **Modern Toolchain**: Clang 22+, LLD, ThinLTO, C++26.
    - **Hardening Flags**: `-fstack-protector-strong`, `-fstack-clash-protection`, `-D_FORTIFY_SOURCE=3`, `-fcf-protection=full`, `-ftrivial-auto-var-init=zero`, PIE + full RELRO.
    - **Minimal Dependencies**: limited external libraries to reduce the TCB.

### PAM Authentication
Voix delegates authentication to the system's PAM configuration.

- **Risk**: PAM conversation hijacking; failure to clean up session credentials; account-state bypass.
- **Mitigation**:
    - **Explicit Lifecycle**: `start` → `authenticate` → `acct_mgmt` → `setcred` → `open_session` → `close_session`.
    - **Account Validation Always Runs**: expired or disabled accounts cannot execute commands even under `trust`/`nopass` rules.
    - **Sensitive Data Handling**: terminal echo disabled around prompts; password buffers zeroed via volatile writes with a compiler barrier.
    - **Session Hygiene**: an RAII guard closes the PAM session even when command execution throws.

### Persisted Authentication Timestamps (`persist`)
- **Risk**: attackers pre-planting or tampering with ticket files to inherit a session.
- **Mitigation**:
    - Tickets live under `<sanctuary>/timestamp/`, created and forced to mode `0700`, owned by the effective UID.
    - Ticket files are written/read exclusively through `O_NOFOLLOW` descriptors with owner and write-bit verification.
    - Future-dated tickets (clock skew or tampering) are rejected; TTL is 15 minutes.
    - `voix -k` removes the invoking user's ticket on demand.

### Signal Handling & Privilege Transition
A critical window of vulnerability exists between `fork()` and `execv()`.
- **Risk**: signal-based attacks interrupting the transition.
- **Mitigation**:
    - **Atomic Signal Blocking**: `pthread_sigmask(SIG_BLOCK)` blocks all signals before `fork()`; the privilege transition is uninterruptible.
    - **Handler Reset**: the child explicitly resets every handler to `SIG_DFL` before executing the target command.
    - **No NSS After Fork**: target identity (UID/GID/groups/home/shell) is fully resolved *before* `fork()`; the child performs no name-service lookups that could deadlock on inherited locks.

### Environment Sanitization
Environment variables (like `LD_PRELOAD` or `BASH_ENV`) are classic vectors for privilege escalation.
- **Risk**: shell escapes or library injection via the inherited environment.
- **Mitigation**:
    - **Strict Whitelisting**: by default the environment is dropped and only `TERM`, `DISPLAY`, `XAUTHORITY`, `LANG`, `PATH` survive, with `PATH` overridden to trusted directories.
    - **Dangerous Name/Prefix Filtering**: even `keepenv` runs strip `BASH_ENV`, `ENV`, `IFS`, `CDPATH`, `GCONV_PATH`, `GETCONF_DIR`, `HOSTALIASES` and any `LD_*`, `CC`, `CXX`, `CMAKE_`, `PERL*`, `PYTHON*`, `RUBY*` variable.
    - **Policy-Gated Preservation**: environment preservation requires a `keepenv` rule grant; the CLI `-E` flag alone can never widen it.
    - **Forced umask**: the child sets `umask(022)` so callers cannot influence file modes of privileged operations.
    - **Explicit Identity Setting**: `USER`, `LOGNAME`, and `HOME` come from the resolved target identity, never the caller.

### Command Execution
Once authenticated, Voix executes the target command with elevated privileges.
- **Risk**: catastrophic commands, PATH hijacking, argument trickery.
- **Mitigation**:
    - **Catastrophic Detection** (hardcoded): basename-matched destruction tools (`fdisk`, `sfdisk`, `cfdisk`, `parted`, `wipe`, `wipefs`, `shred`, `mkswap`, `mkfs*` family), `dd` to raw block devices (sd/hd/vd/nvme/mmcblk/dm/mapper/disk aliases/root device), and `rm -rf` variants targeting `/` — including globs, long options, combined short flags, and cwd-relative paths that canonicalize to `/`.
    - **Configurable Blocklist**: exact-path entries plus `regex:` patterns matched against the canonicalized command line.
    - **Root-Owned Resolution**: resolved executables must be regular files owned by `root` with no group/world write bits, verified via `O_NOFOLLOW` + `fstat`.

---

## 4. Technical Defenses

### Linux Capabilities (`libcap`)
Voix employs the principle of least privilege using Linux capabilities for non-privileged targets.
- **Non-Privileged Targets**: all capabilities are stripped via `Security::dropCapabilities()` before the target command executes — zero inherited root powers.
- **Privileged Targets** (root, package manager): full capabilities are retained since voix's purpose includes granting legitimate root-level operations (pacman hooks need `CAP_CHOWN`, snapper needs snapshots, etc.).

### Syscall Filtering (`libseccomp`)
To prevent non-privileged commands from compromising the kernel, Voix implements a syscall blacklist covering 19 calls:

<details>
<summary>Blacklisted syscalls</summary>

| Category | Syscalls |
| :--- | :--- |
| Kernel/image | `kexec_load`, `bpf` |
| Modules | `init_module`, `finit_module`, `delete_module` |
| System state | `reboot`, `swapon`, `swapoff` |
| Process inspection | `ptrace`, `process_vm_readv`, `process_vm_writev` |
| Kernel objects | `userfaultfd`, `perf_event_open`, `io_uring_setup` |
| Keyring | `keyctl`, `add_key`, `request_key` |
| Handle-based FS escape | `open_by_handle_at`, `name_to_handle_at` |

</details>

- **Scope**: applied only to non-privileged targets; privileged targets require unrestricted syscall access for legitimate operations.
- **NNP Decoupling**: `PR_SET_NO_NEW_PRIVS` is enforced unconditionally for non-privileged targets — even when seccomp is disabled by policy, executed setuid binaries can never regain privileges.
- **Enforcement**: the filter loads in the child after the privilege transition but before `execv`; per-rule `ENOSYS`/`EOPNOTSUPP` responses (architectures lacking a syscall) are tolerated while any other filter error fails closed via `_exit(1)`.

While a blacklist provides immediate security benefits, a default-deny **allowlist policy** remains the recommended future enhancement.

---

## 5. Summary Comparison

| Feature | Traditional Tools | Voix | Why it matters |
| :--- | :--- | :--- | :--- |
| **Complexity** | Massive legacy base | Minimal C++26 core | Smaller attack surface, easier audit |
| **Environment** | Complex keep/reset | Strict whitelist/scrub | Prevents `LD_PRELOAD` and shell escapes |
| **Kernel defense** | External (AppArmor) | Integrated (seccomp + NNP) | Blocks `ptrace`/`kexec`/`bpf` for non-privileged targets |
| **Privileges** | Root (all-or-nothing) | Tiered (full root or zero caps) | Non-privileged targets get zero capabilities |
| **Auth sessions** | Per-tty tickets | Per-UID hardened tickets + always-on acct validation | Convenience without skipping account expiry checks |
| **Audit trail** | Varies | Escaped, symlink-resistant dual logging + outcome-only `nolog` mode | Trustworthy logs, privacy option without blind spots |
| **Config** | Sudoers (complex) | YAML (structured) | Transparent and less prone to syntax errors |
