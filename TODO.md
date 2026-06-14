# Voix TODO

- [x] **Native `auditd` Integration**: Replace custom `/var/log/voix.log` with native Linux Audit framework integration for SIEM compatibility and tamper-evident logging.
- [x] **Path Resolution Hardening**: Implement rigorous check against symlink-based TOCTOU vulnerabilities for resolved binary paths.
- [x] **`voix --check-config` Mode**: Develop a CLI tool to validate the `voix.conf` schema and check path permissions before execution.
- [ ] **Performance Profiling**: Run `perf` analysis on `Command::execute` and `PermissionChecker::permit` to ensure sub-millisecond overhead compared to `sudo`.
