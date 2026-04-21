# Voix Project Roadmap

This document outlines the planned improvements, security hardening, and architectural evolution of Voix.

## 🛡️ Security

### Hardening

- [ ] **Environment Sanitization**: Fix Environment Variable Leakage during `-E` preservation (sanitize `LD_*`, `BASH_ENV`, etc.).
- [ ] **Environment Whitelisting**: Restrict Default Environment Whitelist to exclude compiler variables (`CC`, `CXX`, `CMAKE_*`).

### Completed Security Items

- [x] Implement fail-closed logic in `dropCapabilities` to terminate process on failure.
- [x] Integrate `applySeccompBlacklist` into the execution flow.
- [x] Expand Seccomp blacklist to include more dangerous syscalls (e.g., `ptrace`, `bpf`).
- [x] Implement Strict Capability Bounding in child processes.
- [x] Adopt Command Allowlist model.
- [x] Fix Privilege Escalation via `LD_LIBRARY_PATH`.
- [x] Fix Command Injection in Login Shells.
- [x] Enforce absolute paths for command resolution.
- [x] Fix TOCTOU in Path Sanitization using `realpath`.
- [x] Prevent File Descriptor leaks and reset resource limits.
- [x] Correct logic in `Security::validateContext` (`geteuid` vs `getuid`).
- [x] Resolve identities to UIDs/GIDs during configuration loading.
- [x] Use `libcap` for necessary capabilities.
- [x] Ensure `voix.conf` is immutable (root-owned, restricted permissions).
- [x] Implement Binary Hardening (CFI, ThinLTO, Shadow Call Stack).

## ⚙️ Configuration

### Enhancements

- [ ] **Remote Management**: Exploration of remote configuration synchronization.

### Completed Configuration Items

- [x] Update `src/config.cpp` to support all rule options (e.g., `keepenv`, `nolog`).
- [x] Add `login_shell` and `seccomp` global toggles to the YAML configuration.
- [x] Implement Command Aliases.
- [x] Environment variable preservation during escalation.
- [x] Fully implement `sanctuary:` and `path:` settings.
- [x] Rigorous configuration parameter validation.
- [x] Zero-Copy Lexer using `std::string_view`.

## 🧪 Testing & Quality

### Testing

- [ ] **Custom Test Suite**: Complete the custom test suite (WIP), covering Authenticator, PermissionChecker, and Security modules.
- [-] **Fuzzing Rituals**: `libFuzzer` harnesses for config parser (Deferred).

### Quality & Robustness

- [ ] **C++26 Reflection**: Explore reflection-based configuration parsing (Future).

### Completed Quality Items

- [x] Integrate `std::expected` for consistent error handling.
- [x] Audit `PamUtils` for memory leaks.
- [x] Replace non-thread-safe system calls.
- [x] Use `close_range` for secure FD handling.
- [x] RAII wrappers for C-APIs (`cap_t`, `pam_handle`).
- [x] Modernize string handling with `std::string_view`.
- [x] Use type-safe C++ casts.
- [x] Migrate to `std::filesystem`.
- [x] Standardize on `std::format` and `std::print`.
- [x] Integrate Address and Undefined Behavior sanitizers.
- [x] Clean codebase with Clang-Tidy (`bugprone`, `performance`).

## 🚀 Future & Maintenance

### Deferred Features

- [-] **Plugins of the Void**: Plugin system.
- [-] **The Eternal Scribe**: Automated man page generation.

### Completed Maintenance Items

- [x] Adjust AUR packaging to track version tags (e.g., v4.1.2).
- [x] Implement Resource Limiting (RLIMIT).
- [x] Signal handling during fork-exec.
- [x] Authenticator abstraction.
- [x] Feature-rich shell experience (`-s` / `--login`).
- [x] Secure `/var/log/voix/` permissions.
- [x] Dynamic log severities and multi-plane echoing.
- [x] Test resilience on other Unix-like planes.
