# Threat Model and Security Architecture

Voix is a privilege management tool designed to replace `sudo` with a more transparent, minimal, and strictly controlled security model. This document outlines the attack surface, threat model, and the technical mitigations implemented to ensure system integrity.

## 1. Threat Model

The primary threat actor is a **local authenticated user** attempting to gain unauthorized root privileges or execute privileged operations beyond their assigned scope.

### Attack Vectors
- **Configuration Tampering**: Attempting to modify `/etc/voix.conf` to grant themselves elevated privileges.
- **Binary Exploitation**: Leveraging memory corruption or logic flaws in the setuid binary to bypass authentication or execute arbitrary code.
- **Authentication Bypass**: Manipulating PAM interactions or exploiting flaws in the `PamAuthenticator` logic.
- **Command Injection/Abuse**: Using permitted commands to escape the intended restriction (e.g., via shell escapes or environment variable manipulation).
- **Kernel Exploitation**: Using the elevated privileges granted by Voix to execute dangerous system calls that compromise the kernel.

---

## 2. Attack Surface Analysis

### The Configuration File (`/etc/voix.conf`)
The configuration file defines the entire security policy. If a user can write to this file, they effectively own the system.
- **Risk**: YAML parsing vulnerabilities or unauthorized file modification.
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
    - **Minimal Dependencies**: Limited use of external libraries to reduce the TCB (Trusted Computing Base).

### PAM Authentication
Voix delegates authentication to the system's PAM configuration.
- **Risk**: PAM conversation hijacking or failure to properly clean up session credentials.
- **Mitigation**:
    - **Explicit Lifecycle**: The `PamAuthenticator` strictly follows the `start` $\rightarrow$ `authenticate` $\rightarrow$ `acct_mgmt` $\rightarrow$ `setcred` $\rightarrow$ `open_session` sequence.
    - **Sensitive Data Handling**: `pam_conversation` disables terminal echo to prevent password leakage.

### Command Execution
Once authenticated, Voix executes a target command with elevated privileges.
- **Risk**: Execution of "catastrophic" commands or path traversal.
- **Mitigation**:
    - **Catastrophic Command Blocklist**: Hardcoded prevention of high-risk operations (e.g., `rm -rf /`).
    - **Safe Path Verification**: `Security::isSafePath` prevents access to sensitive files like `/etc/shadow` unless explicitly permitted.
    - **Regex Blocklist**: Administrators can define forbidden command patterns in the config.

---

## 3. Technical Defenses

### Linux Capabilities (`libcap`)
Rather than operating as a monolithic root user, Voix employs the principle of least privilege using Linux capabilities.
- **Dynamic Escalation**: Voix only raises specific capabilities (`CAP_AUDIT_WRITE`, `CAP_DAC_READ_SEARCH`, `CAP_SETUID`) when strictly necessary.
- **Immediate Drop**: Capabilities are stripped via `Security::dropCapabilities()` before the target command is executed, ensuring the child process does not inherit unnecessary root powers.

### Syscall Filtering (`libseccomp`)
To prevent the executed command from compromising the kernel, Voix implements a syscall blacklist.
- **Blacklisted Calls**: Dangerous syscalls including `kexec_load`, `delete_module`, `init_module`, `reboot`, and `ptrace` are blocked.
- **Enforcement**: The filter is applied in the child process after privilege transition but before `execvp`, ensuring that even a compromised privileged process cannot perform these actions.

---

## 4. Comparison with `sudo`

| Feature | `sudo` | Voix |
| :--- | :--- | :--- |
| **Config Complexity** | High (Sudoers syntax) | Low (Structured YAML) |
| **Privilege Model** | Monolithic Root | Fine-grained Capabilities |
| **Kernel Protection** | Minimal/External | Integrated Seccomp Blacklist |
| **TCB Size** | Large | Minimal |
| **Auditability** | High (but complex) | Very High (Transparent & Small) |
