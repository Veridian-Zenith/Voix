/**
 * @file command.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "command.hpp"
#include "exit_code.hpp"
#include "file_utils.hpp"
#include "logger.hpp"
#include "security.hpp"
#include "system_utils.hpp"
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>

#include <cstdlib>
#include <filesystem>
#include <format>
#include <ranges>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

extern char **environ;

namespace Voix {

SecurityProfile Command::resolve_profile(const Config &config, const Rule &rule,
                                         std::string_view target_user) {
  const bool target_unconfined = config.is_unconfined_target(target_user);

  SecurityProfile profile = config.get_profile(rule.profile);
  if (rule.profile.empty() && target_unconfined) {
    // Designated initializers keep this readable and make an added profile
    // field a compile error rather than a silently misaligned value.
    profile = SecurityProfile{
        .retain_full_capabilities = true,
        .enable_seccomp = false,
        .enable_resource_limits = false,
        .scrub_environment = false,
        .preserve_full_environment = true,
        .seccomp_mode = std::string(k_seccomp_mode_blacklist),
        .seccomp_allow = {},
    };
  }

  // Unconfined targets always keep their full environment, regardless of the
  // selected profile, because package managers and AUR helpers require it.
  if (target_unconfined) {
    profile.preserve_full_environment = true;
  }

  return profile;
}

int Command::execute(const ExecutableInfo &command,
                     const std::vector<std::string> &args, const Config &config,
                     const CommandOptions &options, const Rule &rule,
                     const UserIdentity &target) {
  // Resolve and pin the actual executable before fork(). For a login shell
  // the executed file is the target's shell; the named command is passed to
  // that shell with -c. In both cases fexecve() uses this exact descriptor,
  // so replacing the path after validation cannot change what runs.
  FileUtils file_utils(executable_owner_);
  ExecutableInfo executable = command;
  if (options.login_shell) {
    const std::string shell =
        target.shell.empty() ? "/bin/sh" : target.shell;
    auto resolved_shell = file_utils.resolve_executable(shell, "");
    if (!resolved_shell) {
      Logger().report_error(
          ExitCode::NoExec,
          std::format("target login shell is not a safe executable: '{}'",
                      shell),
          "the target's shell must be a root-owned, non-writable executable; "
          "check the passwd entry");
      return exit_status(ExitCode::NoExec);
    }
    executable = *resolved_shell;
  }

  auto opened = file_utils.open_executable(executable);
  if (!opened) {
    Logger().report_error(
        ExitCode::NoExec,
        std::format("executable changed or became unsafe after validation: {}",
                    executable.path),
        "retry the command; if it persists, check that the executable is "
        "root-owned and not writable by group or others");
    return exit_status(ExitCode::NoExec);
  }
  const int executable_fd = *opened;

  sigset_t old_mask;
  if (!block_signals_for_fork(old_mask)) {
    close(executable_fd);
    return exit_status(ExitCode::Software);
  }

  pid_t pid = fork();

  if (pid == -1) {
    Logger().report_error(ExitCode::Software,
                          std::format("fork() failed: {}",
                                      std::strerror(errno)),
                          "the system may be out of process slots or memory");
    close(executable_fd);
    pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
    return exit_status(ExitCode::Software);
  } else if (pid == 0) {
    // -----------------------------------------------------------------------
    // Child process — single-shot, no return. Every _exit() below is the
    // terminal failure path; only fexecve() / _exit() ends the child.
    // -----------------------------------------------------------------------
    reset_child_signals_and_umask(old_mask);

    // Record the execution intent while still privileged and before the FD
    // scrub. The audit file is root-owned, and writing it after the privilege
    // transition could silently lose the durable copy.
    if (!(rule.options & Rule::NOLOG)) {
      LOG_INFO(std::format("executing command: {}, profile: {}",
                           command.policy_path, rule.profile));
    }

    // Profile resolution order (see Command::resolve_profile):
    //   1. An explicit profile named on the rule (administrator's decision).
    //   2. The target is a configured unconfined system target (e.g. the
    //      package-manager user) -> full "system" treatment.
    //   3. Otherwise the safe restricted default.
    const std::string target_name =
        target.username.empty() ? "root" : target.username;
    SecurityProfile profile = resolve_profile(config, rule, target_name);

    auto saved_env = collect_sanitized_environment(profile, options);

    apply_privilege_transition(target);

    apply_capability_drop(profile);

    apply_environment(profile, config, options, rule, target,
                      std::move(saved_env));

    const int exec_fd =
        apply_resource_limits_and_close_fds(profile, executable_fd);

    apply_kernel_confinement(profile, config);

    do_exec(command.policy_path, args, options, target, exec_fd);
    _exit(127); // unreachable; do_exec either succeeds or _exit()s itself
  } else {
    // Parent process
    close(executable_fd);
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
      Logger().report_error(
          ExitCode::Software,
          std::format("waitpid() failed for pid {}: {}", pid,
                      std::strerror(errno)),
          "the child may still be running; check the process table");
      (void)pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);
      return exit_status(ExitCode::Software);
    }

    if (pthread_sigmask(SIG_SETMASK, &old_mask, nullptr) != 0) {
      Logger().report_warning("process.signal-mask",
                              "parent failed to restore the signal mask");
      // Non-fatal, continue.
    }

    if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    }
    // A child killed by a signal reports 128+signum, matching sudo/doas
    // convention, instead of collapsing every signal death to -1/255.
    if (WIFSIGNALED(status)) {
      return 128 + WTERMSIG(status);
    }
    Logger().report_error(ExitCode::Software,
                          "child process ended with an unknown wait status");
    return exit_status(ExitCode::Software);
  }
}

// ---- Pipeline stages --------------------------------------------------------

bool Command::block_signals_for_fork(sigset_t &out_old_mask) {
  sigset_t new_mask;
  sigfillset(&new_mask);
  if (pthread_sigmask(SIG_BLOCK, &new_mask, &out_old_mask) != 0) {
    Logger().report_error(ExitCode::Software,
                          "failed to block signals before fork()");
    return false;
  }
  return true;
}

void Command::reset_child_signals_and_umask(const sigset_t &old_mask) {
  if (pthread_sigmask(SIG_SETMASK, &old_mask, nullptr) != 0) {
    Logger().report_error(ExitCode::Software,
                          "child failed to restore the signal mask");
    _exit(exit_status(ExitCode::Software));
  }

  for (int i = 1; i < NSIG; ++i) {
    signal(i, SIG_DFL);
  }
  umask(022);
}

std::vector<std::pair<std::string, std::string>>
Command::sanitize_environment(const SecurityProfile &profile,
                              const CommandOptions &options,
                              std::span<const std::string> raw_env) {
  const bool preserve_full_env = profile.preserve_full_environment;
  // Two independent grants: the rule's `keepenv` option and the profile's
  // `scrub_environment: false`. Both mean "keep the caller's environment
  // after the dangerous-variable filter"; full preservation is separate.
  const bool preserve_sanitized_env =
      !preserve_full_env && (options.preserve_env || !profile.scrub_environment);

  const std::vector<std::string> whitelist = {"TERM", "DISPLAY", "XAUTHORITY",
                                              "LANG", "PATH"};
  const std::array<std::string_view, 7> dangerous_env_names = {
      "BASH_ENV",   "ENV",         "IFS",        "CDPATH",
      "GCONV_PATH", "GETCONF_DIR", "HOSTALIASES"};
  const std::array<std::string_view, 7> dangerous_env_prefixes = {
      "LD_", "CC", "CXX", "CMAKE_", "PERL", "PYTHON", "RUBY"};

  std::vector<std::pair<std::string, std::string>> env;
  for (const auto &entry : raw_env) {
    const size_t pos = entry.find('=');
    if (pos == std::string::npos)
      continue;
    std::string key = entry.substr(0, pos);
    if (!preserve_full_env) {
      const bool is_dangerous_name =
          std::ranges::find(dangerous_env_names, std::string_view{key}) !=
          dangerous_env_names.end();
      const bool is_dangerous_prefix = std::ranges::any_of(
          dangerous_env_prefixes,
          [&](std::string_view prefix) { return key.starts_with(prefix); });
      if (preserve_sanitized_env && (is_dangerous_name || is_dangerous_prefix))
        continue;
      if (!preserve_sanitized_env &&
          std::ranges::find(whitelist, key) == whitelist.end())
        continue;
    }
    env.emplace_back(key, entry.substr(pos + 1));
  }
  return env;
}

std::vector<std::pair<std::string, std::string>>
Command::collect_sanitized_environment(const SecurityProfile &profile,
                                       const CommandOptions &options) {
  std::vector<std::string> raw_env;
  extern char **environ;
  for (char **e = ::environ; *e != nullptr; ++e) {
    raw_env.emplace_back(*e);
  }
  return sanitize_environment(profile, options, raw_env);
}

void Command::apply_privilege_transition(const UserIdentity &target) {
  auto fail = [&target](std::string_view what) {
    Logger().report_error(
        ExitCode::NoExec,
        std::format("could not switch to target '{}': {}: {}",
                    target.username, what, std::strerror(errno)),
        "the account may be locked or Voix may lack the required privileges");
    _exit(exit_status(ExitCode::NoExec));
  };

  if (!target.groups.empty() &&
      setgroups(target.groups.size(), target.groups.data()) != 0) {
    fail("setgroups()");
  }
  if (setgid(target.gid) != 0) {
    fail("setgid()");
  }
  if (setuid(target.uid) != 0) {
    fail("setuid()");
  }
}

void Command::apply_capability_drop(const SecurityProfile &profile) {
#ifdef VOIX_WITH_CAP
  if (!profile.retain_full_capabilities) {
    Security sec;
    sec.dropCapabilities({});
  }
  // Privileged tier: capabilities are intentionally retained (package
  // managers need CAP_CHOWN etc.). Nothing is dropped here.
#else
  (void)profile;
#endif
}

std::vector<std::pair<std::string, std::string>>
Command::build_environment(
    const SecurityProfile &profile, const Config &config,
    const CommandOptions &options, const Rule &rule, const UserIdentity &target,
    std::vector<std::pair<std::string, std::string>> saved_env) {
  const bool preserve_full_env = profile.preserve_full_environment;
  // See collect_sanitized_environment(): `keepenv` and `scrub_environment:
  // false` both preserve the caller's environment after sanitization.
  const bool preserve_sanitized_env =
      !preserve_full_env && (options.preserve_env || !profile.scrub_environment);

  auto set_entry = [](std::vector<std::pair<std::string, std::string>> &env,
                      std::string_view key, std::string_view value) {
    for (auto &entry : env) {
      if (entry.first == key) {
        entry.second = value;
        return;
      }
    }
    env.emplace_back(std::string(key), std::string(value));
  };

  if (!preserve_full_env && !preserve_sanitized_env) {
    set_entry(saved_env, "PATH", config.getPath());
  }
  set_entry(saved_env, "USER", target.username);
  set_entry(saved_env, "LOGNAME", target.username);

  // A login shell must never inherit the caller's HOME: with keepenv or an
  // unconfined target it would otherwise read the caller's startup files as
  // the target. -H requests the same override for non-login commands.
  if (options.set_home || options.login_shell) {
    set_entry(saved_env, "HOME", target.home_dir);
  }
  if (options.login_shell) {
    set_entry(saved_env, "SHELL", target.shell);
  }

  // Administrator-specified rule env (KEY=VALUE entries applied after
  // sanitization and identity overrides).
  for (const auto &entry : rule.envlist) {
    const auto eq = entry.find('=');
    if (eq != std::string::npos) {
      set_entry(saved_env, std::string_view(entry).substr(0, eq),
                std::string_view(entry).substr(eq + 1));
    }
  }

  return saved_env;
}

void Command::apply_environment(
    const SecurityProfile &profile, const Config &config,
    const CommandOptions &options, const Rule &rule, const UserIdentity &target,
    std::vector<std::pair<std::string, std::string>> saved_env) {
  clearenv();
  for (const auto &[key, value] :
       build_environment(profile, config, options, rule, target,
                         std::move(saved_env))) {
    setenv(key.c_str(), value.c_str(), 1);
  }
}

int Command::apply_resource_limits_and_close_fds(
    const SecurityProfile &profile, int executable_fd) {
  // Capture the original NOFILE limit before any reduction so the close
  // loop covers all inherited descriptors.
  struct rlimit original_rl;
  bool have_original_rl = (getrlimit(RLIMIT_NOFILE, &original_rl) == 0);

  if (profile.enable_resource_limits) {
    setResourceLimits(); // Fatal on failure — never fail open.
  }

  // FD-management invariant:
  //   - Restricted tier scrubs all inherited FDs (>=3) so voix internal
  //     descriptors never leak into the executed command. The pinned
  //     executable descriptor is the sole exception and is moved to fd 3.
  //   - Privileged tier deliberately retains inherited FDs (e.g. D-Bus
  //     sockets for pacman hooks; alpm needs to talk back to the session
  //     bus for download progress). This is by design and documented in
  //     THREATS.md (see CONTRIBUTING.md for the completed v4.12.0 roadmap entry).
  if (!profile.retain_full_capabilities) {
    int kept_fd = executable_fd;
    if (kept_fd != 3) {
      if (dup2(kept_fd, 3) == -1) {
        Logger().report_error(
            ExitCode::NoExec,
            std::format("failed to preserve the executable descriptor: {}",
                        std::strerror(errno)));
        _exit(exit_status(ExitCode::NoExec));
      }
      close(kept_fd);
      kept_fd = 3;
    }

    bool closed = false;
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 4, ~0U, 0) == 0) {
      closed = true;
    }
#endif

    if (!closed) {
      constexpr rlim_t k_fallback_max_fd = 4096;
      constexpr rlim_t k_close_loop_cap = 65536;
      rlim_t max_fd_limit = k_fallback_max_fd;
      if (have_original_rl) {
        max_fd_limit = std::min(original_rl.rlim_cur, k_close_loop_cap);
      }
      int max_fd = static_cast<int>(max_fd_limit);
      for (int i : std::views::iota(4, max_fd)) {
        close(i);
      }
    }

    return kept_fd;
  }

  return executable_fd;
}

void Command::apply_kernel_confinement(const SecurityProfile &profile,
                                       const Config &config) {
  if (profile.retain_full_capabilities) {
    // Privileged tier: no NNP, no seccomp. Package managers rely on the
    // ambient ability to re-acquire capabilities via setuid helpers.
    return;
  }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    Logger().report_error(ExitCode::NoExec,
                          "failed to set PR_SET_NO_NEW_PRIVS",
                          "the kernel may be too old or seccomp is "
                          "unsupported");
    _exit(exit_status(ExitCode::NoExec));
  }
#ifdef VOIX_WITH_SECCOMP
  if (profile.seccomp_mode == k_seccomp_mode_allowlist) {
    Security sec;
    sec.applySeccompAllowlist(profile.seccomp_allow);
  } else if (profile.seccomp_mode == k_seccomp_mode_blacklist) {
    if (config.is_seccomp_enabled() && profile.enable_seccomp) {
      Security sec;
      sec.applySeccompBlacklist();
    }
  } else {
    // Fail closed: an unrecognized mode must never be read as "no filter".
    // Configuration validation rejects this earlier; this is the backstop.
    Logger().report_error(
        ExitCode::Config,
        std::format("unknown seccomp_mode '{}'", profile.seccomp_mode),
        "use 'blacklist' or 'allowlist' in the security profile");
    _exit(exit_status(ExitCode::Config));
  }
#else
  (void)profile;
  (void)config;
#endif
}

void Command::do_exec(const std::string &cmd_str,
                      const std::vector<std::string> &args,
                      const CommandOptions &options,
                      const UserIdentity &target, int executable_fd) {
  auto escape = [](const std::string &s) {
    std::string escaped = "'";
    for (char c : s) {
      if (c == '\'')
        escaped += "'\\''";
      else
        escaped += c;
    }
    escaped += '\'';
    return escaped;
  };

  // fexecve() requires a descriptor that is not close-on-exec. The descriptor
  // is pinned to the inode validated before fork(), so path replacement after
  // validation cannot redirect execution.
  const int fd_flags = fcntl(executable_fd, F_GETFD);
  // Clear FD_CLOEXEC without a signed bitwise operation (FD_CLOEXEC is an
  // int constant; the flags word is conceptually unsigned).
  const auto without_cloexec = static_cast<int>(
      static_cast<unsigned int>(fd_flags) &
      ~static_cast<unsigned int>(FD_CLOEXEC));
  if (fd_flags == -1 ||
      fcntl(executable_fd, F_SETFD, without_cloexec) == -1) {
    Logger().report_error(
        ExitCode::NoExec,
        std::format("failed to prepare the executable descriptor: {}",
                    std::strerror(errno)));
    _exit(exit_status(ExitCode::NoExec));
  }

  if (options.login_shell) {
    // Login mode uses the POSIX argv[0] leading-dash convention ("-bash"),
    // which every shell understands, instead of the "-l" option that
    // dash/sh reject.
    const std::string shell =
        target.shell.empty() ? "/bin/sh" : target.shell;
    std::string login_argv0 =
        "-" + std::filesystem::path(shell).filename().string();
    std::string c_arg = "-c";
    std::string full_cmd = escape(cmd_str);
    for (const auto &arg : args) {
      full_cmd += " " + escape(arg);
    }

    const char *args_exec[] = {login_argv0.c_str(), c_arg.c_str(),
                               full_cmd.c_str(), nullptr};
    fexecve(executable_fd, const_cast<char *const *>(args_exec), environ);
    Logger().report_error(
        ExitCode::NoExec,
        std::format("could not execute login shell '{}': {}",
                    std::filesystem::path(shell).filename().string(),
                    std::strerror(errno)));
    _exit(exit_status(ExitCode::NoExec));
  }

  std::vector<const char *> argv;
  argv.push_back(cmd_str.c_str());
  for (const auto &arg : args) {
    argv.push_back(arg.c_str());
  }
  argv.push_back(nullptr);
  fexecve(executable_fd, const_cast<char *const *>(argv.data()), environ);
  Logger().report_error(
      ExitCode::NoExec,
      std::format("could not execute '{}': {}", cmd_str,
                  std::strerror(errno)),
      "the executable may be missing its interpreter or have invalid "
      "permissions");
  _exit(exit_status(ExitCode::NoExec));
}

void Command::setResourceLimits() const {
  struct rlimit rl;

  // Limit open file descriptors
  rl.rlim_cur = 1024;
  rl.rlim_max = 4096;
  if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
    Logger().report_error(
        ExitCode::NoExec,
        std::format("failed to set RLIMIT_NOFILE: {}", std::strerror(errno)));
    _exit(exit_status(ExitCode::NoExec));
  }

  // Limit number of processes to prevent fork bombs
  rl.rlim_cur = 512;
  rl.rlim_max = 1024;
  if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
    Logger().report_error(
        ExitCode::NoExec,
        std::format("failed to set RLIMIT_NPROC: {}", std::strerror(errno)));
    _exit(exit_status(ExitCode::NoExec));
  }

  // Limit core dump size (prevent sensitive memory from being written to disk)
  rl.rlim_cur = 0;
  rl.rlim_max = 0;
  if (setrlimit(RLIMIT_CORE, &rl) != 0) {
    Logger().report_error(
        ExitCode::NoExec,
        std::format("failed to set RLIMIT_CORE: {}", std::strerror(errno)));
    _exit(exit_status(ExitCode::NoExec));
  }
}

} // namespace Voix
