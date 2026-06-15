# Packaging Voix

This directory contains resources for packaging Voix for various Linux distributions.

## General Information

- **Build System**: Voix uses CMake with Ninja.
- **Compiler**: Requires LLVM/Clang (C++26).
- **Dependencies (Runtime/Build)**:
  - `yaml-cpp`
  - `pam`
  - `libcap`
  - `libseccomp`
- **Permissions**: The binary requires `setuid` permissions (`root:root`, `4755`).

## Distribution-Specific Notes

### Debian/Ubuntu (.deb)
- **Dependencies**: `libyaml-cpp-dev`, `libpam0g-dev`, `libcap-dev`, `libseccomp-dev`.
- **Packaging**: Ensure `setuid` permissions are applied to `/usr/bin/voix` in the post-install script.

### Fedora/RHEL (.rpm)
- **Dependencies**: `yaml-cpp-devel`, `pam-devel`, `libcap-devel`, `libseccomp-devel`.
- **Packaging**: Ensure `setuid` permissions are applied to `/usr/bin/voix` in the post-install script.
