# Packaging Voix

This directory contains resources for packaging Voix for various Linux distributions and the Arch User Repository (AUR).

## Build System

- **Build System**: CMake with Ninja
- **Compiler**: Requires LLVM/Clang (C++26). Clang-only; GCC is not supported.
- **CMake**: 3.30+ required (uses C++26 standard features)

## Optional Features (compile-time)

Voix supports optional runtime security features that can be toggled at build time via CMake options:

| CMake Option | Default | Purpose |
| :--- | :--- | :--- |
| `VOIX_ENABLE_CAP` | `ON` | Linux capabilities management via `libcap` |
| `VOIX_ENABLE_SECCOMP` | `ON` | Syscall filtering via `libseccomp` |
| `ENABLE_PERMISSIONS` | `ON` | Set `setuid` on install (disable for packaging; set manually) |
| `VOIX_STATIC_YAML_CPP` | `OFF` | Statically link yaml-cpp so the binary carries no versioned soname requirement (used by the release workflow; recommended for prebuilt packages) |

A minimal build with only `yaml-cpp` and `pam` is possible by disabling the two optional features.

## AUR Packaging

Two AUR packages are provided:

### `voix` (source build)

Builds from source. Requires the full LLVM toolchain at build time.

- **AUR path**: `AUR/voix/`
- **makedepends**: `cmake>=3.30`, `clang`, `lld`, `ninja`, `pkgconf`, `ccache`
- **provides/conflicts**: `sudo`, `doas` (Voix replaces these entirely)

### `voix-bin` (pre-built binary)

Installs pre-built binaries from GitHub Releases. No compiler toolchain needed at build time.

- **AUR path**: `AUR/voix-bin/`
- **Source**: Built binary uploaded to GitHub Releases as `voix-x86_64-bin.tar.gz`
- **makedepends**: None (no compilation required)
- **provides/conflicts**: `sudo`, `doas`, and `voix` (use `voix-bin` when you do not want to compile)

### Updating AUR packages

1. Bump `pkgver`/`pkgrel` in both `pkg/voix/PKGBUILD` and `pkg/voix-bin/PKGBUILD`
2. Update `source` URLs to the new release tag
3. Regenerate `.SRCINFO` (`makepkg --printsrcinfo > .SRCINFO`)
4. Compute checksums for source tarball (`makepkg --printsrcinfo` or `updpkgsums`)
5. Commit and push to the `pkg/voix` and `pkg/voix-bin` AUR git checkouts

## Multi-Arch Notes

Supported architectures: `x86_64` (primary) and `aarch64` (AUR expanded, cross-compile via `clang --target=aarch64-linux-gnu`).

32-bit (`i386`/`i686`) is intentionally not supported: the minimal TCB, modern C++26 toolchain (clang 22+), `libcap`, `libseccomp`, PIE + full RELRO hardening, and the setuid-root execution model assume a 64-bit environment. No CI job, AUR entry, or release artifact is provided for 32-bit.

## Multi-Arch Cross-Compile

Direct mechanism (verified, v4.12.0):

```bash
clang++ --target=aarch64-linux-gnu -std=c++26 -fexperimental-library \
  -Iinclude $(find src -name '*.cpp' | grep -v main | tr '\n' ' ') \
  -lpam -lcap -lseccomp -lyaml-cpp -fPIE -flto=thin
```

Note: `armv8-a` is not a native clang CPU value; use `aarch64-linux-gnu` target triple. CMake `VOIX_ARCH=native` applies `-march=native` which overrides cross-target; disable or override for multi-arch builds.

AUR `arch`: expanded to `('x86_64' 'aarch64')` in `pkg/voix/PKGBUILD` and `pkg/voix-bin/PKGBUILD`.

## Debian/Ubuntu (.deb)

- **Dependencies**: `libyaml-cpp3`, `libpam0g`, `libcap2`, `libseccomp2`
- **Build dependencies**: `cmake`, `clang`, `ninja-build`, `pkg-config`
- **Packaging**: Use `dpkg-buildpackage` or `debuild`. Ensure `setuid` is set on `/usr/bin/voix` in `debian/rules` post-install hook.

## Fedora/RHEL (.rpm)

- **Dependencies**: `yaml-cpp`, `pam`, `libcap`, `libseccomp`
- **Build dependencies**: `cmake`, `clang`, `ninja-build`, `pkgconf`
- **Packaging**: Use `rpmbuild`. Ensure `setuid` is set on `/usr/bin/voix` in the `%post` script.

## Configuration Files

Regardless of packaging format, the following paths are standard:

| Path | Description |
| :--- | :--- |
| `/usr/bin/voix` | Binary (setuid root, mode 4755) |
| `/etc/voix.conf` | Configuration file (root-owned, mode 0600) |
| `/etc/pam.d/voix` | PAM service configuration |
| `/var/lib/voix` | Sanctuary directory (persisted authentication timestamps) |
| `/usr/share/man/man1/voix.1` | Man page (if packaged) |

> [!IMPORTANT]
> Never overwrite a live `/etc/voix.conf` on upgrade: install the shipped
> sample as `/etc/voix.conf.new` instead (the CMake install step already does
> this). Pacman-based packaging achieves the same via `backup=('etc/voix.conf'
> 'etc/pam.d/voix')` in the PKGBUILD.
