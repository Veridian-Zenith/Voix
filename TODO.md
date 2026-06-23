# Voix TODO

- [x] **Path Resolution Hardening**: Implement rigorous check against symlink-based TOCTOU vulnerabilities for resolved binary paths.
- [x] **`voix --check-config` Mode**: Develop a CLI tool to validate the `voix.conf` schema and check path permissions before execution.
- [x] **Environment Sanitization Hardening for Privileged Users**: Unconditionally filter out dangerous environment variables (e.g., `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, `IFS`) for privileged users (`root`/`alpm`) while preserving essential variables (`DBUS_SESSION_BUS_ADDRESS`, etc.) to prevent privilege escalation.
- [x] **Configurable Privileged Users**: Externalize the hardcoded `"alpm"` package manager string in [system_utils.hpp](file:///home/dae/VZ_Dev/work/Voix/include/system_utils.hpp) to a configurable block in [voix.conf](file:///home/dae/VZ_Dev/work/Voix/config/voix.conf).
- [ ] **Granular Security Policies**: Allow specifying seccomp and capability rules directly in [voix.conf](file:///home/dae/VZ_Dev/work/Voix/config/voix.conf) rather than using hardcoded child execution bypasses.
- [ ] **Internal File Descriptor Leak Audit**: Ensure all files and socket handles opened internally (e.g. PAM connections or config streams) are marked `CLOEXEC`/`CLOFORK` to avoid leaking handles to hook subprocesses.
