# Threat Model and Security Architecture

Voix is a Privilege Policy Enforcement Runtime designed to supersede traditional privilege escalation tools with a more transparent, minimal, and strictly controlled security model. This document outlines the attack surface, threat model, and the technical mitigations implemented to ensure system integrity.

## 1. TCB Metrics (Trusted Computing Base)

To ensure transparency and auditability, Voix maintains a minimal TCB. Unlike traditional tools that have grown complex over decades, Voix is designed for a narrow, high-assurance scope.

| Metric | Traditional Tools (approx.) | Voix | Note |
| :--- | :--- | :--- | :--- |
| **Lines of Code** | ~180,000 | ~3,375 | $\sim$53x smaller attack surface |
| **External Dependencies** | Many (varies) | 1 required, 3 optional | `yaml-cpp` (required); `pam`, `libcap`, `libseccomp` (optional) |
| **Binary Size (Release)** | ~1.2 MB | 418 KB | Highly optimized via Clang/LTO |
| **Config Language** | Sudoers (Custom) | YAML (Standard) | Reduced parsing complexity |
| **CVE History** | Extensive | 0 | New design eliminates legacy bugs |

---

## 2. Threat Model

The primary threat actor is a **local authenticated user** attempting to gain unauthorized root privileges or execute privileged operations beyond their assigned scope.

### Attack Vectors
- **Configuration Tampering**: Attempting to modify `/etc/voix.conf` to grant themselves elevated privileges.
- **Binary Exploitation**: Leveraging memory corruption or logic flaws in the setuid binary to bypass authentication or execute arbitrary code.
- **Authentication Bypass**: Manipulating PAM interactions or exploiting flaws in the `PamAuthenticator` logic.
- **Command Injection/Abuse**: Using permitted commands to escape the intended restriction (e.g., via shell escapes or environment variable manipulation).
- **Kernel Exploitation**: Using the elevated privileges granted by Voix to execute dangerous system calls that compromise the kernel.

---

## 3. Attack Surface Analysis

### The Configuration File (`/etc/voix.conf`)
The configuration file defines the entire security policy. If a user can write to this file, they effectively own the system.
- **Risk**: YAML parsing vulnerabilities in `yaml-cpp` or unauthorized file modification.
- **Mitigation**: 
    - **Strict Ownership**: Voix verifies that `/etc/voix.conf` and its parent directory are owned by `root`.
    - **Strict Permissions**: The file must not be group-writable or world-writable.
    - **Secure Path Validation**: `FileUtils::isSecurePath` enforces these checks before the configuration is parsed.

### The Setuid Binary
To transition from a standard user to root, Voix must be installed as setuid root.
- **Risk**: Memory safety issues (buffer overflows, use-after-free) in C++ code.
- **Mitigation**:
    - **Modern Toolchain**: Built with Clang and LLD/MOLD using C++26.
    - **Hardening Flags**: Compiled with `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, and `-fPIE`.
    - **Minimal Dependencies**: Limited use of external libraries to reduce the TCB.

### PAM Authentication
Voix delegates authentication to the system's PAM configuration.
- **Risk**: PAM conversation hijacking or failure to properly clean up session credentials.
- **Mitigation**:
    - **Explicit Lifecycle**: The `PamAuthenticator` strictly follows the `start` $\rightarrow$ `authenticate` $\rightarrow$ `acct_mgmt` $\rightarrow$ `setcred` $\rightarrow$ `open_session` sequence.
    - **Sensitive Data Handling**: `pam_conversation` disables terminal echo to prevent password leakage.

### Signal Handling & Privilege Transition
A critical window of vulnerability exists between `fork()` and `execv()`.
- **Risk**: Signal-based attacks (e.g., interrupting the transition to inject code).
- **Mitigation**:
    - **Atomic Signal Blocking**: Voix uses `pthread_sigmask` to block all signals (`SIG_BLOCK`) before the `fork()` call, ensuring the privilege transition is uninterruptible.
    - **Handler Reset**: In the child process, all signal handlers are explicitly reset to `SIG_DFL` before executing the target command.

### Environment Sanitization
Environment variables (like `LD_PRELOAD` or `BASH_ENV`) are classic vectors for privilege escalation.
- **Risk**: Shell escapes or library injection via inherited environment.
- **Mitigation**:
    - **Strict Whitelisting**: By default, Voix drops the entire environment and restores only a minimal whitelist (`TERM`, `DISPLAY`, `XAUTHORITY`, `LANG`, `PATH`).
    - **Dangerous Prefix Blocking**: Even when `preserve_env` is enabled, Voix explicitly filters out dangerous variables (e.g., `LD_*`, `BASH_ENV`, `ENV`, `CC`, `CXX`).
    - **Explicit Identity Setting**: `USER`, `LOGNAME`, and `HOME` are forcefully set from the system password database.

### Command Execution
Once authenticated, Voix executes a target command with elevated privileges.
- **Risk**: Execution of "catastrophic" commands or path traversal.
- **Mitigation**:
    - **Catastrophic Command Blocklist**: Hardcoded prevention of high-risk operations (e.g., `rm -rf /`).
    - **Configurable Blocklist**: Administrators can extend this via the YAML `blocklist` to forbid additional tools.
    - **Safe Path Verification**: `Security::isSafePath` prevents access to sensitive files like `/etc/shadow` unless explicitly permitted.

---

## 4. Technical Defenses

### Linux Capabilities (`libcap`)
Voix employs the principle of least privilege using Linux capabilities for non-privileged target users.
- **Non-Privileged Targets**: All capabilities are stripped via `Security::dropCapabilities()` before the target command is executed, ensuring the child process has zero inherited root powers.
- **Privileged Targets** (root, package manager): Full capabilities are retained since voix's purpose is to grant root-level access. Restricting capabilities for root targets would break legitimate operations (e.g., pacman hooks, snapper, systemd operations).

### Syscall Filtering (`libseccomp`)
To prevent non-privileged commands from compromising the kernel, Voix implements a syscall blacklist.
- **Blacklisted Calls**: Dangerous syscalls including `kexec_load`, `delete_module`, `init_module`, `finit_module`, `reboot`, `swapon`, `swapoff`, `ptrace`, and `bpf` are blocked.
- **Scope**: Seccomp and `PR_SET_NO_NEW_PRIVS` are applied only to non-privileged target users. Privileged targets require unrestricted syscall access for legitimate operations (package manager hooks, process management, etc.).
- **Enforcement**: The filter is applied in the child process after privilege transition but before `execv`. While traditional tools often rely on external AppArmor/SELinux profiles, Voix provides integrated kernel-level protection for non-privileged targets by default.

---

## 5. Summary Comparison

| Feature | Traditional Tools | Voix | Why it matters |
| :--- | :--- | :--- | :--- |
| **Complexity** | Massive Legacy Base | Minimal C++26 Core | Smaller attack surface, easier audit |
| **Environment** | Complex Keep/Reset | Strict Whitelist/Scrub | Prevents `LD_PRELOAD` and shell escapes |
| **Kernel Defense**| External (AppArmor) | Integrated (Seccomp) | Blocks `ptrace`/`kexec` for non-privileged targets |
| **Privileges** | Root (All-or-Nothing) | Tiered (full root or zero caps) | Non-privileged targets get zero capabilities |
| **Config** | Sudoers (Complex) | YAML (Structured) | Transparent and less prone to syntax errors |
