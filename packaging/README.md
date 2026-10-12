# Packaging Voix

This directory contains resources for packaging Voix for various Linux distributions and the Arch User Repository (AUR).

## Table of Contents

- [Build System](#build-system)
- [Optional Features (compile-time)](#optional-features-compile-time)
- [AUR Packaging](#aur-packaging)
  - [`voix` (source build)](#voix-source-build)
  - [`voix-bin` (pre-built binary)](#voix-bin-pre-built-binary)
  - [Release signing (GPG)](#release-signing-gpg)
  - [Updating AUR packages](#updating-aur-packages)
- [Multi-Arch](#multi-arch)
  - [Supported architectures](#supported-architectures)
  - [Cross-compile](#cross-compile)
  - [Build size notes](#build-size-notes)
- [Distribution Packages](#distribution-packages)
  - [Debian/Ubuntu (.deb)](#debianubuntu-deb)
  - [Fedora/RHEL (.rpm)](#fedorarhel-rpm)
- [Configuration Files](#configuration-files)

---

## Build System

| Aspect | Requirement |
| :--- | :--- |
| **Build system** | CMake + Ninja |
| **Compiler** | LLVM/Clang with C++26 (Clang-only; GCC is not supported) |
| **CMake** | 3.30+ (uses C++26 standard features) |

## Optional Features (compile-time)

Voix supports optional runtime security features that can be toggled at build time via CMake options:

| CMake Option | Default | Purpose |
| :--- | :--- | :--- |
| `VOIX_ENABLE_CAP` | `ON` | Linux capabilities management via `libcap` |
| `VOIX_ENABLE_SECCOMP` | `ON` | Syscall filtering via `libseccomp` |
| `ENABLE_PERMISSIONS` | `ON` | Set `setuid` on install (disable for packaging; set manually) |
| `VOIX_STATIC_YAML_CPP` | `OFF` | Statically link yaml-cpp so the binary carries no versioned soname requirement (used by the release workflow; recommended for prebuilt packages) |

A minimal build with only `yaml-cpp` and `pam` is possible by disabling the two optional features.

---

## AUR Packaging

Two AUR packages are provided:

### `voix` (source build)

Builds from source. Requires the full LLVM toolchain at build time.

| Field | Value |
| :--- | :--- |
| **AUR path** | `AUR/voix/` |
| **Source** | Signed tagged source archive `voix-src-<ver>.tar.gz` (+ detached `.asc`) from the GitHub release |
| **makedepends** | `cmake>=3.30`, `clang`, `lld`, `ninja`, `pkgconf`, `ccache` |
| **provides/conflicts** | `sudo`, `doas` (Voix replaces these entirely) |

### `voix-bin` (pre-built binary)

Installs pre-built binaries from GitHub Releases. No compiler toolchain needed at build time.

| Field | Value |
| :--- | :--- |
| **AUR path** | `AUR/voix-bin/` |
| **Source** | Built binary `voix-x86_64-bin.tar.gz` (+ detached `voix-x86_64-bin.tar.gz.asc`) from GitHub Releases |
| **makedepends** | None (no compilation required) |
| **provides/conflicts** | `sudo`, `doas`, and `voix` (use `voix-bin` when you do not want to compile) |

### Release signing (GPG)

Every release artifact — both prebuilt tarballs and the tagged source archive — is published together with a detached, armored GPG signature (`<artifact>.asc`). Both PKGBUILDs pin the signing key via `validpgpkeys`, so `makepkg` verifies the signature *in addition to* the SHA-256 checksum before it extracts or builds anything. This gives two independent trust chains: the checksum proves the bytes were not altered, and the signature proves who produced them.

| Item | Value |
| :--- | :--- |
| **Key** | Primary ed25519 release key |
| **Fingerprint** | `7887165D6B07DE7785BD536E5239ACB42207EE03` (Dae Euhwa `<daedaevibin@ik.me>`) |
| **Public key** | Published on keys.openpgp.org |
| **CI secrets** | Armored private key as `GPG_PRIVATE_KEY`, its passphrase as `GPG_PASSPHRASE` |
| **Workflow** | [`.github/workflows/release.yml`](../.github/workflows/release.yml) signs each artifact and uploads the `.asc` next to its tarball |

Verify a downloaded artifact by hand:

```bash
gpg --recv-keys 7887165D6B07DE7785BD536E5239ACB42207EE03
gpg --verify voix-x86_64-bin.tar.gz.asc voix-x86_64-bin.tar.gz
sha256sum -c <(printf '%s  %s\n' "<sha256 from .SRCINFO>" voix-x86_64-bin.tar.gz)
```

> [!NOTE]
> AUR helpers (`paru`, `yay`) fetch a missing `validpgpkeys` entry automatically
> from a keyserver. Plain `makepkg` does not, so import the key once by hand
> (command above) before the first build.

### Updating AUR packages

1. Bump `pkgver`/`pkgrel` in both `pkg/voix/PKGBUILD` and `pkg/voix-bin/PKGBUILD`
2. Update the `source` / `source_<arch>` URLs to the new release tag
3. Recompute checksums with `updpkgsums` (the `.asc` entries stay `SKIP`)
4. Regenerate `.SRCINFO` (`makepkg --printsrcinfo > .SRCINFO`)
5. Commit and push to the `pkg/voix` and `pkg/voix-bin` AUR git checkouts

> [!NOTE]
> The checksum and the GPG signature are independent trust chains: the checksum
> proves the bytes were not altered, the signature proves who produced them. To
> check an artifact by hand: `gpg --verify <artifact>.asc <artifact>` must report
> `Good signature from` the release key
> (`7887165D6B07DE7785BD536E5239ACB42207EE03`).

---

## Multi-Arch

### Supported architectures

`x86_64` (primary) and `aarch64` (cross-compile via `clang --target=aarch64-linux-gnu`).

> [!IMPORTANT]
> 32-bit (`i386`/`i686`) is intentionally **not** supported: the minimal TCB,
> modern C++26 toolchain (clang 22+), `libcap`, `libseccomp`, PIE + full RELRO
> hardening, and the setuid-root execution model all assume a 64-bit
> environment. No CI job, AUR entry, or release artifact is provided for 32-bit.

### Cross-compile

Direct mechanism (verified, v4.12.0):

```bash
clang++ --target=aarch64-linux-gnu -std=c++26 -fexperimental-library \
  -Iinclude $(find src -name '*.cpp' | grep -v main | tr '\n' ' ') \
  -lpam -lcap -lseccomp -lyaml-cpp -fPIE -flto=thin
```

> [!NOTE]
> `armv8-a` is not a native clang CPU value; use the `aarch64-linux-gnu` target
> triple. CMake's `VOIX_ARCH=native` applies `-march=native`, which overrides the
> cross-target — disable or override it for multi-arch builds.

AUR `arch` is expanded to `('x86_64' 'aarch64')` in both `pkg/voix/PKGBUILD` and `pkg/voix-bin/PKGBUILD`.

### Build size notes

Measured by running `makepkg -s` in each AUR directory on x86_64 (v4.13.3):

| Build | Binary | Package (`.pkg.tar.zst`) | Installed |
| :--- | :--- | :--- | :--- |
| Distro (`pkg/voix`, dynamic `yaml-cpp`) | **511,352 B** (~499 KiB) | **236,004 B** — `du -sh` 232K | **518,176 B** (~506 KiB) |
| Portable (`pkg/voix-bin`, bundled `yaml-cpp`) | **794,392 B** (~776 KiB) | **340,155 B** — `du -sh` 336K | **801,216 B** (~782 KiB) |

A local Release build (`build/voix`) measured the same 511,352 B as the distro package
binary. Bundling `yaml-cpp` adds ~283 KB (794 KB vs 511 KB) but removes the versioned
`libyaml-cpp.so.N` soname requirement — the distro build links `libyaml-cpp`
dynamically (`ldd`), the portable one does not. "Installed" is the `size =` field
inside the package's `.PKGINFO`.

> [!NOTE]
> `voix` (distro) is compiled locally by every user, so its size varies with
> toolchain and flags — the figures above are the author's reference baseline.
> `voix-bin` ships a pre-built binary and is therefore reproducible.

Cross-compiled `aarch64` size is not verified here (needs an aarch64 sysroot); the
release pipeline ([`.github/workflows/release.yml`](../.github/workflows/release.yml))
produces both `voix-x86_64-bin.tar.gz` (native) and `voix-aarch64-bin.tar.gz` (cross).

---

## Distribution Packages

### Debian/Ubuntu (.deb)

| Field | Value |
| :--- | :--- |
| **Dependencies** | `libyaml-cpp3`, `libpam0g`, `libcap2`, `libseccomp2` |
| **Build dependencies** | `cmake`, `clang`, `ninja-build`, `pkg-config` |
| **Packaging** | Use `dpkg-buildpackage` or `debuild`. Ensure `setuid` is set on `/usr/bin/voix` in the `debian/rules` post-install hook. |

### Fedora/RHEL (.rpm)

| Field | Value |
| :--- | :--- |
| **Dependencies** | `yaml-cpp`, `pam`, `libcap`, `libseccomp` |
| **Build dependencies** | `cmake`, `clang`, `ninja-build`, `pkgconf` |
| **Packaging** | Use `rpmbuild`. Ensure `setuid` is set on `/usr/bin/voix` in the `%post` script. |

---

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
> Never overwrite a live `/etc/voix.conf` on upgrade: install the shipped sample
> as `/etc/voix.conf.new` instead (the CMake install step already does this).
> Pacman-based packaging achieves the same via `backup=('etc/voix.conf'
> 'etc/pam.d/voix')` in the PKGBUILD.

For the command-line interface, see [docs/CLI.md](../docs/CLI.md).
