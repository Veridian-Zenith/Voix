# Code Review: Voix Privilege Policy Enforcement Runtime

## 1. Executive Summary

The Voix codebase implements a high-assurance privilege execution broker. The architecture has transitioned from a "utility" mindset to a "runtime" mindset, and the implementation reflects this shift. The system effectively manages a strictly ordered execution pipeline that minimizes the attack surface through defense-in-depth layering.

**Overall Assessment:** The implementation is technically sound, follows modern C++26 standards, and correctly implements the security invariants required for a privileged execution broker.

---

## 2. Architecture & Pipeline Analysis

### 2.1 Execution Pipeline Verification
The codebase correctly implements the staged pipeline defined in the system specification:

| Stage | Implementation Location | Verification |
| :--- | :--- | :--- |
| **Policy Evaluation** | `PermissionChecker::permit` | $\checkmark$ Deterministic ACL matching |
| **Authentication** | `PamAuthenticator::authenticate` | $\checkmark$ PAM stack delegation |
| **Privilege Transition**| `Command::execute` (L105-116) | $\checkmark$ `initgroups` $\rightarrow$ `setgid` $\rightarrow$ `setuid` |
| **Capability Reduction**| `Security::dropCapabilities` | $\checkmark$ `cap_clear` for non-privileged targets |
| **Syscall Confinement** | `Security::applySeccompBlacklist` | $\checkmark$ `PR_SET_NO_NEW_PRIVS` $\rightarrow$ `seccomp_load` |
| **Env Sanitization** | `Command::execute` (L68-154) | $\checkmark$ Whitelist/Blacklist scrubbing |
| **Process Execution** | `Command::execute` (L253) | $\checkmark$ `execv` call |

### 2.2 Execution Tiering
The distinction between **Privileged** and **Non-Privileged** targets is explicitly handled via the `is_privileged_user` flag in `Command::execute`. 
- **Non-Privileged:** Full confinement (Capabilities $\rightarrow$ Resource Limits $\rightarrow$ FD Closing $\rightarrow$ Seccomp).
- **Privileged:** Employs an alternate execution profile with relaxed enforcement to ensure compatibility with system-level operations (e.g., package manager hooks). This creates a reduced security boundary for privileged targets by design.

---

## 3. Security Deep Dive

### 3.1 Memory Safety & Modern C++
- **Standard:** Uses C++26 features (`std::expected`, `std::ranges`, `std::format`, `std::print`).
- **Resource Management:** Extensive use of `std::unique_ptr` with custom deleters for C-style handles (`cap_t`, `scmp_filter_ctx`), preventing leaks in the privileged path.
- **Exception Safety:** `main.cpp` uses a top-level `try-catch` block. While this reduces the general failure surface, it does not replace atomic transition guarantees enforced at the process boundary level.

### 3.2 Privilege Transition Correctness
The sequence in `Command::execute` is correct:
1. `initgroups()` $\rightarrow$ sets supplementary groups.
2. `setgid()` $\rightarrow$ sets primary group.
3. `setuid()` $\rightarrow$ sets user identity.
This order is critical to prevent a process from using root privileges to change its group after it has already dropped root user privileges.

### 3.3 Environment Sanitization
The sanitization logic in `Command::execute` (L68-103) is robust:
- **Blacklist approach** for `preserve_env`: Explicitly blocks `LD_`, `BASH_ENV`, etc.
- **Whitelist approach** for default: Only allows a minimal set of variables (`TERM`, `LANG`, etc.).
- This effectively mitigates common `LD_PRELOAD` and shell-injection attacks.

### 3.4 Path & File Security
- **Symmetry of Checks:** `FileUtils::isSecurePath` and `Security::isSafePath` provide dual-layer protection.
- **Traversal Prevention:** Use of `std::filesystem::weakly_canonical` and explicit `..` checks prevents directory traversal attacks.
- **Ownership Verification:** Strict enforcement that configuration files must be owned by `root` and not be world/group writable.

### 3.5 Syscall Filtering
Seccomp filters are applied in the child process prior to `exec`, after privilege transition, and strictly under the `PR_SET_NO_NEW_PRIVS` constraint. This ensures the filter cannot be bypassed by executing a setuid binary.

---

## 4. Logic & Implementation Observations

### 4.1 Policy Evaluation
`PermissionChecker` implements first-match semantics. If a `DENY` rule matches before a `PERMIT` rule, the action is denied. This is a secure default. Variable resolution (`%u`) is implemented simply and effectively.

### 4.2 PAM Integration
`PamAuthenticator` correctly implements the PAM lifecycle:
`pam_start` $\rightarrow$ `pam_authenticate` $\rightarrow$ `pam_acct_mgmt` $\rightarrow$ `pam_setcred` $\rightarrow$ `pam_open_session`.
The use of `explicit_bzero` in `pam_conversation` ensures that passwords are wiped from memory immediately after use.

---

## 5. Potential Improvements & Recommendations

### 5.1 FD Closing Optimization
In `Command::execute` (L178-189), the fallback loop for closing file descriptors is linear. While `close_range` is used when available, the fallback could be optimized or replaced with a more robust mechanism for systems where `close_range` is missing but `RLIMIT_NOFILE` is very high.

### 5.2 Seccomp Policy Evolution
The current **blacklist** policy is a pragmatic choice for compatibility. For future hardening, implementing a **whitelist (default-deny)** policy for specific high-risk rites would significantly increase the security posture.

### 5.3 Policy Semantics & Performance
The use of `std::regex` for the global blocklist introduces potential ambiguity in policy evaluation semantics. Beyond performance concerns, the complexity of regex matching can lead to unexpected authorization results. For a high-assurance system, migrating to a more deterministic matching engine or a formal grammar would be advisable.

---

## 6. Additional Review Findings (July 2026)

### 6.1 TOCTOU in Config Loading
**Severity: Medium** — `FileUtils::isSecurePath()` and `std::filesystem::is_symlink()` are checked against the config path before `YAML::LoadFile()` opens it. An attacker with write access to the parent directory could swap the file between check and load. Fix: open the file with `O_NOFOLLOW` first, then `fstat()` the fd and read via `read()` into the YAML parser.

### 6.2 Portable Memory Zeroing
`explicit_bzero()` (src/pam_utils.cpp:58) is a glibc extension (2.25+) and unavailable on musl-based systems (Alpine, etc.). Use `memset_s()` (C11 Annex K) or a portable volatile-function-pointer-based memset wrapper.

### 6.3 Broad Capability Raise
`Security::raiseCapabilities()` raises `CAP_DAC_READ_SEARCH` for config file access. This is a broad capability for a narrow need. Consider raising `CAP_DAC_OVERRIDE` or opening the config file before dropping capabilities.

### 6.4 Monolithic Command Execution
`Command::execute()` spans ~276 lines, handling signal blocking, privilege transition, capability drop, environment sanitization, resource limits, FD closing, seccomp, and exec. Decomposing into smaller focused methods would improve maintainability.

### 6.5 Catastrophic Command False Positives
`isCatastrophicCommand()` uses `std::string::find("mkfs")`, which matches any path containing "mkfs" (e.g., `mkfs-my-usb`). Exact command matching is safer.

### 6.6 Test File Monolith
All 58 unit tests reside in a single `tests/test_runner.cpp` (1039 lines). Splitting per module would improve organization and parallelism.

---

## 7. Final Verdict

<div style="background-color: #e6ffed; border: 1px solid #b7eb8f; padding: 15px; border-radius: 5px; color: #22863a; font-weight: bold; text-align: center;">
  STATUS: No critical implementation-level flaws identified in the privilege transition and enforcement pipeline under intended trust assumptions.
</div>

The codebase successfully implements the **Privilege Policy Enforcement Runtime** specification. There are no immediate critical vulnerabilities identified in the privilege transition or policy enforcement logic.
