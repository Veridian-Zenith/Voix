# =========================================================
# Base
# =========================================================
source /usr/share/cachyos-fish-config/cachyos-config.fish
fish_add_path /home/dae/.spicetify

# =========================================================
# LLVM / Clang Toolchain
# =========================================================
# Core compiler & tools
set -Ux CC clang
set -Ux CXX clang++
set -Ux LD ld.lld
set -Ux AR llvm-ar
set -Ux NM llvm-nm
set -Ux STRIP llvm-strip
set -Ux OBJCOPY llvm-objcopy
set -Ux OBJDUMP llvm-objdump
set -Ux READELF llvm-readelf
set -Ux AS clang
set -Ux HOSTCC clang
set -Ux HOSTCXX clang++

# Optimization, hardening, and quiet warnings
set -Ux CFLAGS "-march=native -O3 -pipe -fno-plt \
-Wno-unused-variable -Wno-unused-parameter -Wno-unused-function \
-Wno-unused-but-set-variable -Wno-missing-field-initializers \
-Wno-sign-compare -Wno-unused-result"

set -Ux CXXFLAGS "$CFLAGS"

set -Ux LDFLAGS "-fuse-ld=mold -Wl,-O1,--as-needed,-z,relro,-z,now"
set -Ux CPPFLAGS "-D_FORTIFY_SOURCE=3"
set -Ux LTOFLAGS "-flto=thin"

# LLVM build tuning
set -Ux LLVM_PARALLEL_LINK_JOBS (nproc)
set -Ux LLVM_ENABLE_LLD 1
set -Ux LLVM_ENABLE_LTO thin

# ccache
set -Ux CCACHE_DIR /var/cache/ccache
set -Ux CCACHE_MAXSIZE 20G

# =========================================================
# Rust Toolchain (LLVM-aligned + optimized)
# =========================================================
# Ensure Rust uses the LLVM linker and LTO + quiet warnings
set -Ux RUSTFLAGS "-C linker=clang -C link-arg=-fuse-ld=lld -C lto=thin \
-A dead_code -A unused_variables -A unused_imports"

# Incremental builds off (fully deterministic)
set -Ux CARGO_INCREMENTAL 0

# Force target dir to cache builds
set -Ux CARGO_TARGET_DIR "$HOME/.cargo/build"

# Optional: enable verbose backtraces for debugging
set -Ux RUST_BACKTRACE 1

# =========================================================
# Build Systems (CMake / Make / Ninja)
# =========================================================
set -Ux CMAKE_C_FLAGS "$CFLAGS"
set -Ux CMAKE_CXX_FLAGS "$CXXFLAGS"
set -Ux CMAKE_EXE_LINKER_FLAGS "$LDFLAGS"
set -Ux CMAKE_SHARED_LINKER_FLAGS "$LDFLAGS"
set -Ux MAKEFLAGS "-s"
set -Ux NINJA_STATUS ""

# =========================================================
# Defaults (Hyprland / UWSM)
# =========================================================
set -gx terminal kitty
set -gx fileManager nemo
set -gx menu rofi -show drun
set -gx browser naver-whale-stable
set -gx textEditor mousepad

# =========================================================
# Utilities & Loaders
# =========================================================
function oneapi
    bass source /opt/intel/oneapi/setvars.sh
end

alias vtune-gui 'env ELECTRON_OZONE_PLATFORM_HINT=x11 vtune-gui'

# =========================================================
# System Maintenance
# =========================================================
alias cmem 'sudo sync; and echo 3 | sudo tee /proc/sys/vm/drop_caches; and sudo swapoff -a; and sudo systemctl daemon-reexec; and sudo systemctl restart systemd-zram-setup@zram0'
alias trim 'sudo fstrim -av'
alias ls 'ls -lh'

# =========================================================
# Package Management (Paru — Alpine Style)
# =========================================================
alias upd         'paru -Syu --noconfirm; and flatpak update -y'
alias fwupd       'fwupdmgr refresh; and fwupdmgr upgrade'
alias add         'paru -S'
alias search      'paru -Ss'
alias del         'paru -Rns --noconfirm'
alias purge       'paru -Rns --noconfirm; and paru -Qtdq | paru -Rns -'
alias orphans     'paru -Qtd'
alias list        'paru -Qe'
alias info        'paru -Si'
alias info-local  'paru -Qi'
alias cache-clean 'sudo rm -rf /var/cache/pacman/pkg/download-*; paru -Sc --noconfirm'


# --- GCR SSH setup for Git ---
# Only run if SSH_AUTH_SOCK is empty
if not set -q SSH_AUTH_SOCK
    # Set it to the GCR default socket
    set -xg SSH_AUTH_SOCK /run/user/1000/gcr/ssh
end

# Wait until the socket actually exists
while not test -S $SSH_AUTH_SOCK
    sleep 0.1
end
