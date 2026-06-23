# Voix TODO

## Core Runtime Hardening
- [ ] **Granular Security Profiles**: Transition from binary "Privileged vs Non-Privileged" tiers to named security profiles in `voix.conf`. Allow policies to specify required capabilities and seccomp profiles per-rule.
- [ ] **Deterministic FD Management**: Conduct a full audit of internal file descriptors (PAM handles, config streams) to ensure all are `O_CLOEXEC`. Implement a strict FD-closing invariant before `execve`.
- [ ] **Formal State Machine Verification**: Define the execution pipeline (Policy $\rightarrow$ Auth $\rightarrow$ Transition $\rightarrow$ Confinement $\rightarrow$ Exec) as a formal state machine to ensure no illegal transitions exist.

## Engineering & Tooling
- [ ] **Negative Security Testing**: Implement a test suite that explicitly attempts to bypass seccomp filters and capability drops using known exploit patterns.
- [ ] **Packaging Automation**: Create standardized build/install scripts for major distributions (Arch, Debian, Fedora) including automated PAM configuration deployment.
- [ ] **Policy Validation Tool**: Expand `--check-config` to perform semantic analysis of policies (e.g., detecting redundant rules or overly permissive patterns).

## Completed
- [x] Path Resolution Hardening (TOCTOU protection)
- [x] `--check-config` Mode
- [x] Environment Sanitization Hardening
- [x] Configurable Privileged Users
