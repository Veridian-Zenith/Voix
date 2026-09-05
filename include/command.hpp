/**
 * @file command.hpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef COMMAND_H
#define COMMAND_H

#include "config.hpp"
#include "rule.hpp"
#include "system_identity.hpp"
#include <string>
#include <string_view>
#include <vector>

namespace Voix {

/**
 * @brief Options for command execution.
 */
struct CommandOptions {
  bool preserve_env =
      false; /**< Whether to preserve the environment variables. */
  bool login_shell =
      false; /**< Whether to execute the command as a login shell. */
  bool list_commands = false; /**< Whether to list available commands. */
  bool check_config = false;  /**< Whether to check configuration. */
};

/**
 * @brief Handles the execution of commands with given options and
 * configuration.
 */
class Command {
public:
  /**
   * @brief Default constructor for Command.
   */
  Command() = default;
  /**
   * @brief Default destructor for Command.
   */
  ~Command() = default;

  /**
   * @brief Executes a command with given arguments and options.
   *
   * All identity resolution happens in the parent before fork(); the child
   * performs no name-service lookups between fork() and execve().
   *
   * @param command The command to execute.
   * @param args The arguments for the command.
   * @param config The configuration to use.
   * @param options The options for command execution.
   * @param rule The matched authorization rule.
   * @param target Fully resolved identity of the target user.
   * @return The return code of the command, or a non-zero value on failure.
   */
  int execute(std::string_view command, const std::vector<std::string> &args,
              const Config &config, const CommandOptions &options,
              const Rule &rule, const UserIdentity &target);

  /**
   * @brief Resolves the security profile to apply for a matched rule and
   * target.
   *
   * Resolution order:
   *   1. An explicit profile named on the rule (administrator's decision).
   *   2. The target is a configured unconfined system target (e.g. the
   *      package manager user) -> the full "system" profile is applied.
   *   3. Otherwise the safe restricted default is applied.
   *
   * Unconfined targets always keep their full environment independently of
   * the selected profile, since package managers and AUR helpers require it.
   *
   * @param config The configuration.
   * @param rule The matched rule.
   * @param target_user The target user name.
   * @return The resolved SecurityProfile.
   */
  static SecurityProfile resolve_profile(const Config &config, const Rule &rule,
                                         std::string_view target_user);

private:
  /**
   * @brief Sets resource limits for the executed command.
   */
  void setResourceLimits() const;

  // ---- execute() pipeline stages ---------------------------------------
  // Each stage owns one logical concern of the child-side execution path.
  // They are private because they only make sense in the order execute()
  // invokes them; they exist purely to keep that method readable and to
  // make the FD-management / privilege-transition invariants auditable.

  /// Block all signals in the calling thread (parent) for the duration of
  /// fork()/waitpid(); restore on return. Returns the prior mask via out.
  bool block_signals_for_fork(sigset_t &out_old_mask);

  /// Restore the prior signal mask, reset all handlers to SIG_DFL and force
  /// umask(022) so the invoking user cannot widen file modes of privileged
  /// operations. Child-side, must be the first step after fork().
  void reset_child_signals_and_umask(const sigset_t &old_mask);

  /// Snapshot the inherited environment according to the resolved profile:
  /// unconfined targets keep everything; granted keepenv strips dangerous
  /// loader/interpreter names + prefixes; otherwise only the safe whitelist
  /// is retained.
  std::vector<std::pair<std::string, std::string>>
  collect_sanitized_environment(const SecurityProfile &profile,
                                const CommandOptions &options);

  /// setgroups -> setgid -> setuid. Supplementary groups were resolved in
  /// the parent before fork(); no name-service activity happens here.
  /// Fatal on any failure (never falls back to a less-privileged identity).
  void apply_privilege_transition(const UserIdentity &target);

  /// Drop capabilities for the restricted tier. No-op (other than the
  /// VOIX_WITH_CAP guard) for the privileged tier, which retains them so
  /// package managers can chown their download directories.
  void apply_capability_drop(const SecurityProfile &profile);

  /// clearenv(), then restore the sanitized snapshot, override PATH/USER/
  /// LOGNAME/HOME, optionally install SHELL (login mode) and apply the
  /// rule's root-defined envlist entries.
  void
  apply_environment(const SecurityProfile &profile, const Config &config,
                    const CommandOptions &options, const Rule &rule,
                    const UserIdentity &target,
                    std::vector<std::pair<std::string, std::string>> saved_env);

  /// Apply profile-driven resource limits and scrub inherited file
  /// descriptors on the restricted tier. Privileged targets deliberately
  /// retain inherited FDs (e.g. D-Bus sockets for pacman hooks); see the
  /// FD-management invariant documented at the close-loop site.
  void apply_resource_limits_and_close_fds(const SecurityProfile &profile);

  /// Resolve a non-absolute command against the configured PATH and reject
  /// anything that does not canonicalize to an absolute path. Returns the
  /// absolute path. _exit(127)s on failure (the child cannot recover).
  std::string resolve_absolute_command(std::string command,
                                       const Config &config);

  /// PR_SET_NO_NEW_PRIVS is unconditional on the restricted tier; seccomp
  /// follows the profile's choice between blacklist and allowlist mode.
  void apply_kernel_confinement(const SecurityProfile &profile,
                                const Config &config);

  /// Login-shell vs direct execv dispatch. _exit(127) on exec failure.
  void do_exec(const std::string &cmd_str, const std::vector<std::string> &args,
               const CommandOptions &options, const UserIdentity &target);
};

} // namespace Voix

#endif // COMMAND_H
