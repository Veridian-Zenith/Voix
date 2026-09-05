/**
 * @file security.cpp
 * @brief Enhanced security implementation
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "security.hpp"
#include "logger.hpp"
#include <unistd.h>
#ifdef VOIX_WITH_CAP
#include <sys/capability.h>
#endif
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <pwd.h>
#include <regex>
#include <sstream>
#include <sys/types.h>
#include <vector>
#ifdef VOIX_WITH_SECCOMP
#include <errno.h>
#include <seccomp.h>
#endif
#include <memory>
#include <sys/stat.h>

namespace Voix {

namespace {

namespace fs = std::filesystem;

/// Basename of a command path ("rm", "/bin/rm" -> "rm").
std::string basename_of(std::string_view command) {
  return fs::path(command).filename().string();
}

/// True for short options containing the given flag char (-rf, -fr, -Rf...).
bool short_flag_has(const std::string &arg, char flag) {
  if (arg.size() < 2 || arg[0] != '-' || arg[1] == '-')
    return false;
  return arg.find(flag) != std::string::npos;
}

/// True for --flag or --flag=value long options.
bool long_flag_is(const std::string &arg, std::string_view name) {
  if (!arg.starts_with("--"))
    return false;
  std::string_view body{arg};
  body.remove_prefix(2);
  const auto eq = body.find('=');
  return body.substr(0, eq) == name;
}

std::optional<std::string> canonicalize_arg(const std::string &raw) {
  try {
    return fs::weakly_canonical(fs::absolute(fs::path(raw))).string();
  } catch (...) {
    return std::nullopt;
  }
}

// True if an rm argument targets the root filesystem itself.
// Covers "/", "//", root globs ("/" + "*" patterns), and any relative or
// traversal form that canonicalizes to "/" from the current directory
// (".", "..", "./", "a/../.." with cwd=/, etc.).
bool rm_targets_root(const std::string &raw) {
  if (raw.empty())
    return false;
  if (raw == "/" || raw == "//")
    return true;

  // Root-level glob: consists only of '/' and '*' characters, starts
  // with '/', and contains at least one '*'.
  bool glob_only = raw.front() == '/';
  bool has_star = false;
  for (char c : raw) {
    if (c != '/' && c != '*') {
      glob_only = false;
      break;
    }
    if (c == '*')
      has_star = true;
  }
  if (glob_only && has_star)
    return true;

  auto canon = canonicalize_arg(raw);
  return canon.has_value() && *canon == "/";
}

/// Destructive tools blocked by basename regardless of path prefix.
constexpr std::string_view k_destructive_basenames[] = {
    "fdisk", "sfdisk", "cfdisk", "parted", "wipe", "wipefs", "shred", "mkswap",
};

/// Raw block-device prefixes that dd must never touch.
constexpr std::string_view k_block_device_prefixes[] = {
    "/dev/sd",     "/dev/hd",    "/dev/vd",  "/dev/nvme", "/dev/mmcblk",
    "/dev/mapper", "/dev/disk/", "/dev/dm-", "/dev/root",
};

} // namespace

#ifdef VOIX_WITH_CAP
struct CapDeleter {
  void operator()(cap_t p) const {
    if (p)
      cap_free(p);
  }
};
using UniqueCap = std::unique_ptr<std::remove_pointer_t<cap_t>, CapDeleter>;
#endif

#ifdef VOIX_WITH_SECCOMP
struct SeccompDeleter {
  void operator()(scmp_filter_ctx ctx) const {
    if (ctx)
      seccomp_release(ctx);
  }
};
using UniqueSeccomp =
    std::unique_ptr<std::remove_pointer_t<scmp_filter_ctx>, SeccompDeleter>;
#endif

Security::Security(std::shared_ptr<IIdentity> identity)
    : identity(std::move(identity)) {}

bool Security::validateUser(std::string_view username) const {
  if (username.empty() || username.length() > 32) {
    return false;
  }

  for (char c : username) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '-') {
      return false;
    }
  }

  return identity->get_user_by_name(std::string(username)).has_value();
}

void Security::logEvent(std::string_view event, std::string_view user) const {
  Logger logger;
  logger.log("SECURITY", std::format("[{}] {}", user, event));
}

std::string Security::getCurrentUser() const {
  return identity->get_current_username();
}

uid_t Security::get_current_uid() const { return identity->get_current_uid(); }

std::string Security::get_root_device() const {
  std::ifstream mounts("/proc/self/mountinfo");
  if (!mounts.is_open())
    return "";

  std::string line;
  while (std::getline(mounts, line)) {
    // mountinfo format: mount-ID parent-ID major:minor root mountpoint
    // mount-options - fstype source [options]
    size_t sep = line.find(" - ");
    if (sep == std::string::npos)
      continue;

    std::string fields_part = line.substr(0, sep);
    std::string after_sep = line.substr(sep + 3);

    std::istringstream iss_fields(fields_part);
    std::string mount_id_str, parent_id_str, major_minor_str, root_str;
    std::string mountpoint;
    if (!(iss_fields >> mount_id_str >> parent_id_str >> major_minor_str >>
          root_str >> mountpoint))
      continue;

    if (mountpoint != "/")
      continue;

    std::istringstream iss_after(after_sep);
    std::string fstype, source;
    if (!(iss_after >> fstype >> source))
      continue;

    if (source.starts_with("/dev/")) {
      return source;
    }
  }
  return "";
}

bool Security::isCatastrophicCommand(std::string_view command,
                                     const std::vector<std::string> &args,
                                     const Config &config) const {
  // Trim surrounding whitespace so trailing-space variants cannot evade
  // the blocklist comparisons below.
  std::string cmd_str{command};
  const auto first = cmd_str.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
    return false;
  const auto last = cmd_str.find_last_not_of(" \t\r\n");
  cmd_str = cmd_str.substr(first, last - first + 1);
  std::string_view cmd{cmd_str};

  // Full command line for admin regex entries; arguments are canonicalized
  // where possible so regexes see absolute paths.
  std::string full_command{cmd};
  for (const auto &arg : args) {
    full_command += " ";
    auto canon = canonicalize_arg(arg);
    full_command += canon.value_or(arg);
  }

  const std::string base = basename_of(cmd);

  if (base == "rm") {
    bool recursive = false;
    bool force = false;
    bool target_root = false;

    for (const auto &arg : args) {
      if (!arg.empty() && arg[0] == '-') {
        recursive |= arg == "-r" || arg == "-R" || short_flag_has(arg, 'r') ||
                     short_flag_has(arg, 'R') || long_flag_is(arg, "recursive");
        force |= arg == "-f" || short_flag_has(arg, 'f') ||
                 long_flag_is(arg, "force");
      } else if (rm_targets_root(arg)) {
        target_root = true;
      }
    }

    if (recursive && force && target_root) {
      return true;
    }
  } else if (base == "dd") {
    std::string root_dev = get_root_device();
    for (const auto &arg : args) {
      // Block dd targeting the root filesystem device
      if (!root_dev.empty() && arg.find(root_dev) != std::string::npos) {
        return true;
      }
      for (auto dev : k_block_device_prefixes) {
        if (arg.find(dev) != std::string::npos) {
          return true;
        }
      }
    }
  } else {
    // Destructive tools by basename: fdisk/sfdisk/cfdisk/parted,
    // wipe/wipefs/shred/mkswap — any path prefix.
    if (std::ranges::find(k_destructive_basenames, base) !=
        std::end(k_destructive_basenames)) {
      return true;
    }
    // Entire mkfs family (mkfs, mkfs.ext4, mkfs.btrfs, ...) plus paths.
    if (base.starts_with("mkfs")) {
      return true;
    }
  }

  // Admin-configured exact-path blocklist entries.
  for (const auto &forbidden_cmd : config.get_blocklist()) {
    if (cmd == forbidden_cmd)
      return true;
  }

  // Admin-configured regex entries ("regex:<pattern>") matched against the
  // canonicalized full command line.
  for (const auto &[pattern, regex] : config.get_regex_blocklist()) {
    (void)pattern;
    if (std::regex_search(full_command, regex)) {
      return true;
    }
  }
  return false;
}

#ifdef VOIX_WITH_CAP
void Security::raiseCapabilities() {
  UniqueCap caps(cap_get_proc());
  if (!caps) {
    throw std::runtime_error("cap_get_proc failed");
  }

  cap_value_t required_caps[] = {CAP_AUDIT_WRITE, CAP_DAC_READ_SEARCH,
                                 CAP_SETUID};
  if (cap_set_flag(caps.get(), CAP_EFFECTIVE, 3, required_caps, CAP_SET) ==
      -1) {
    throw std::runtime_error("cap_set_flag failed");
  }

  if (cap_set_proc(caps.get()) == -1) {
    throw std::runtime_error("Insufficient privileges. Voix must be installed "
                             "setuid root or have proper file capabilities.");
  }
}

void Security::dropCapabilities(const std::vector<cap_value_t> &keep_caps) {
  UniqueCap caps(cap_get_proc());
  if (!caps) {
    LOG_ERROR("Failed to get capabilities before dropping");
    _exit(1);
  }
  if (cap_clear(caps.get()) == -1) {
    LOG_ERROR("Failed to clear capabilities");
    _exit(1);
  }
  if (!keep_caps.empty()) {
    if (cap_set_flag(caps.get(), CAP_PERMITTED, keep_caps.size(),
                     keep_caps.data(), CAP_SET) == -1) {
      LOG_ERROR("Failed to set permitted capabilities to keep");
      _exit(1);
    }
    if (cap_set_flag(caps.get(), CAP_EFFECTIVE, keep_caps.size(),
                     keep_caps.data(), CAP_SET) == -1) {
      LOG_ERROR("Failed to set effective capabilities to keep");
      _exit(1);
    }
  }
  if (cap_set_proc(caps.get()) == -1) {
    LOG_ERROR("Failed to set capabilities (drop)");
    _exit(1);
  }
}
#endif

#ifdef VOIX_WITH_SECCOMP
void Security::applySeccompBlacklist() const {
  UniqueSeccomp ctx(seccomp_init(SCMP_ACT_ALLOW));
  if (!ctx) {
    LOG_WARN("Failed to init seccomp");
    _exit(1);
  }

  // Kernel/module/reboot surface
  const int syscalls[] = {
      SCMP_SYS(kexec_load),
      SCMP_SYS(delete_module),
      SCMP_SYS(init_module),
      SCMP_SYS(finit_module),
      SCMP_SYS(reboot),
      SCMP_SYS(swapon),
      SCMP_SYS(swapoff),
      SCMP_SYS(ptrace),
      SCMP_SYS(bpf),
      SCMP_SYS(userfaultfd),
      SCMP_SYS(perf_event_open),
      SCMP_SYS(keyctl),
      SCMP_SYS(add_key),
      SCMP_SYS(request_key),
      SCMP_SYS(open_by_handle_at),
      SCMP_SYS(name_to_handle_at),
      SCMP_SYS(io_uring_setup),
      SCMP_SYS(process_vm_readv),
      SCMP_SYS(process_vm_writev),
  };

  for (int sc : syscalls) {
    int rc = seccomp_rule_add(ctx.get(), SCMP_ACT_KILL, sc, 0);
    // Tolerate architectures where the syscall does not exist; fail
    // closed on anything else.
    if (rc < 0 && rc != -ENOSYS && rc != -EOPNOTSUPP) {
      LOG_WARN(
          std::format("Failed to add seccomp rule for syscall {}: {}", sc, rc));
      _exit(1);
    }
  }

  if (seccomp_load(ctx.get()) < 0) {
    LOG_ERROR("Failed to load seccomp");
    _exit(1);
  }
}

void Security::applySeccompAllowlist() const {
  // Default-deny allowlist: kill every syscall EXCEPT the 19 permitted
  // ones derived from the current blacklist entry (the recommended future
  // enhancement per THREATS.md §3). This flips the default from ALLOW
  // (blacklist) to KILL (allowlist) and permits only the listed set.
  UniqueSeccomp ctx(seccomp_init(SCMP_ACT_KILL));
  if (!ctx) {
    LOG_WARN("Failed to init seccomp (allowlist)");
    _exit(1);
  }

  const int permitted_syscalls[] = {
      SCMP_SYS(kexec_load),
      SCMP_SYS(delete_module),
      SCMP_SYS(init_module),
      SCMP_SYS(finit_module),
      SCMP_SYS(reboot),
      SCMP_SYS(swapon),
      SCMP_SYS(swapoff),
      SCMP_SYS(ptrace),
      SCMP_SYS(bpf),
      SCMP_SYS(userfaultfd),
      SCMP_SYS(perf_event_open),
      SCMP_SYS(keyctl),
      SCMP_SYS(add_key),
      SCMP_SYS(request_key),
      SCMP_SYS(open_by_handle_at),
      SCMP_SYS(name_to_handle_at),
      SCMP_SYS(io_uring_setup),
      SCMP_SYS(process_vm_readv),
      SCMP_SYS(process_vm_writev),
  };

  for (int sc : permitted_syscalls) {
    int rc = seccomp_rule_add(ctx.get(), SCMP_ACT_ALLOW, sc, 0);
    if (rc < 0 && rc != -ENOSYS && rc != -EOPNOTSUPP) {
      LOG_WARN(std::format("Failed to add allowlist rule for syscall {}: {}",
                           sc, rc));
      _exit(1);
    }
  }

  if (seccomp_load(ctx.get()) < 0) {
    LOG_ERROR("Failed to load seccomp (allowlist)");
    _exit(1);
  }
}
#endif

} // namespace Voix
