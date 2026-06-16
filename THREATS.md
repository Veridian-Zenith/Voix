# Threat Model and Security Architecture

Voix is a privilege management tool designed to replace `sudo` with a more transparent, minimal, and strictly controlled security model. This document outlines the attack surface, threat model, and the technical mitigations implemented to ensure system integrity.

## 1. TCB Metrics (Trusted Computing Base)

To ensure transparency and auditability, Voix maintains a minimal TCB. Unlike traditional tools that have grown complex over decades, Voix is designed for a narrow, high-assurance scope.

| Metric | `sudo` (approx.) | Voix | Note |
| :--- | :--- | :--- | :--- |
| **Lines of Code** | ~180,000 | ~2,800 | $\sim$64x smaller attack surface |
| **External Dependencies** | Many (varies) | 4 | `yaml-cpp`, `libpam`, `libcap`, `libseccomp` |
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
    - **Configurable Blocklist**: Administrators can extend this via the YAML `blocklist` to forbid tools like `mkfs`, `dd`, or `passwd`.
    - **Safe Path Verification**: `Security::isSafePath` prevents access to sensitive files like `/etc/shadow` unless explicitly permitted.

---

## 4. Technical Defenses

### Linux Capabilities (`libcap`)
Rather than operating as a monolithic root user, Voix employs the principle of least privilege using Linux capabilities.
- **Dynamic Escalation**: Voix only raises specific capabilities (`CAP_AUDIT_WRITE`, `CAP_DAC_READ_SEARCH`, `CAP_SETUID`) when strictly necessary.
- **Immediate Drop**: Capabilities are stripped via `Security::dropCapabilities()` before the target command is executed, ensuring the child process does not inherit unnecessary root powers.

### Syscall Filtering (`libseccomp`)
To prevent the executed command from compromising the kernel, Voix implements a syscall blacklist.
- **Blacklisted Calls**: Dangerous syscalls including `kexec_load`, `delete_module`, `init_module`, `finit_module`, `reboot`, `swapon`, `swapoff`, `ptrace`, and `bpf` are blocked.
- **Enforcement**: The filter is applied in the child process after privilege transition but before `execvp`. While `sudo` often relies on external AppArmor/SELinux profiles, Voix provides integrated kernel-level protection by default.

---

## 5. Summary Comparison

| Feature | `sudo` | Voix | Why it matters |
| :--- | :--- | :--- | :--- |
| **Complexity** | Massive Legacy Base | Minimal C++26 Core | Smaller attack surface, easier audit |
| **Environment** | Complex Keep/Reset | Strict Whitelist/Scrub | Prevents `LD_PRELOAD` and shell escapes |
| **Kernel Defense**| External (AppArmor) | Integrated (Seccomp) | Blocks `ptrace`/`kexec` by default |
| **Privileges** | Root (All-or-Nothing) | Fine-grained Capabilities | Limits blast radius of a compromised process |
| **Config** | Sudoers (Complex) | YAML (Structured) | Transparent and less prone to syntax errors |
