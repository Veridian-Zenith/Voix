# Voix TODO

## Core Runtime Hardening
- [ ] **Granular Security Profiles**: Transition from binary "Privileged vs Non-Privileged" tiers to named security profiles in `voix.conf`. Allow policies to specify required capabilities and seccomp profiles per-rule.
- [ ] **Deterministic FD Management**: Conduct a full audit of internal file descriptors (PAM handles, config streams) to ensure all are `O_CLOEXEC`. Implement a strict FD-closing invariant before `execve`.
- [ ] **Formal State Machine Verification**: Define the execution pipeline (Policy $\rightarrow$ Auth $\rightarrow$ Transition $\rightarrow$ Confinement $\rightarrow$ Exec) as a formal state machine to ensure no illegal transitions exist.
- [ ] **TOCTOU-Safe Config Loading**: Replace `stat()`-then-`YAML::LoadFile()` with `O_NOFOLLOW` open + `fstat()` + read-via-fd to prevent symlink-swap attacks between check and load.
- [ ] **Granular Capability Management**: Raise individual capabilities (e.g., `CAP_DAC_OVERRIDE`) instead of `CAP_DAC_READ_SEARCH` for config reading; drop capabilities immediately after privileged operations complete.
- [ ] **Configurable Log Path**: Make `/var/log/voix.log` configurable via `voix.conf` instead of hardcoded.

## Engineering & Tooling
- [ ] **Negative Security Testing**: Implement a test suite that explicitly attempts to bypass seccomp filters and capability drops using known exploit patterns.
- [ ] **Packaging Automation**: Create standardized build/install scripts for major distributions (Arch, Debian, Fedora) including automated PAM configuration deployment.
- [ ] **Policy Validation Tool**: Expand `--check-config` to perform semantic analysis of policies (e.g., detecting redundant rules or overly permissive patterns).
- [ ] **Split Monolithic Test File**: Break `tests/test_runner.cpp` (1039 lines, 58 tests) into per-module test files.
- [ ] **Decompose `Command::execute()`**: Split the ~276-line method into smaller focused functions (signal setup, privilege transition, env sanitization, FD closing, seccomp).
- [ ] **Portable Secure Memory Zeroing**: Replace `explicit_bzero` (glibc-only) with `memset_s` (C11) or volatile-function-pointer-based memset for musl compatibility.
- [ ] **Exact Command Matching for Blocklist**: Fix `isCatastrophicCommand()` to use exact command matching instead of substring `find("mkfs")` to avoid false positives.

## Completed
- [x] Path Resolution Hardening (TOCTOU protection)
- [x] `--check-config` Mode
- [x] Environment Sanitization Hardening
- [x] Configurable Privileged Users
