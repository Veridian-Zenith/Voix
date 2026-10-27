/**
 * @file security.h
 * @brief Enhanced security and validation
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef SECURITY_H
#define SECURITY_H

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#ifdef VOIX_WITH_CAP
#include <sys/capability.h>
#endif
#include "config.hpp"
#include "system_identity.hpp"

namespace Voix {

class Security {
public:
  /**
   * @brief Constructor for Security.
   * @param identity An optional identity provider. Defaults to SystemIdentity.
   */
  Security(
      std::shared_ptr<IIdentity> identity = std::make_shared<SystemIdentity>());
  /**
   * @brief Default destructor for Security.
   */
  ~Security() = default;

  /**
   * @brief Validates that a user exists and is considered safe.
   * @param username Username to validate.
   * @return True if valid, false otherwise.
   */
  bool validateUser(std::string_view username) const;

  /**
   * @brief Logs a security event with a stable audit code.
   * @param code Stable identifier (see audit.hpp).
   * @param event Human-readable detail.
   * @param user Username associated with the event.
   */
  void logEvent(std::string_view code, std::string_view event,
                std::string_view user) const;

  /**
   * @brief Gets the current username.
   * @return The current username.
   */
  std::string getCurrentUser() const;
  /**
   * @brief Gets the current user ID.
   * @return The current UID.
   */
  uid_t get_current_uid() const;

  /**
   * @brief Prevents unequivocally destructive commands (e.g., 'rm -rf /').
   *
   * Detection is basename-based for known destructive tools and
   * canonicalization-aware for filesystem targets (a relative argument that
   * resolves to "/" from the current working directory is caught).
   *
   * @param command Command to check.
   * @param args Command arguments.
   * @param config Configuration instance for the blocklist.
   * @return True if the command is catastrophic, false otherwise.
   */
  bool isCatastrophicCommand(std::string_view command,
                             const std::vector<std::string> &args,
                             const Config &config) const;

private:
  /**
   * @brief Get the root filesystem device path (e.g., /dev/sda2).
   * @return The root device path, or empty string if undetermined.
   */
  std::string get_root_device() const;

public:
#ifdef VOIX_WITH_CAP
  /**
   * @brief Raises capabilities to perform privileged operations.
   */
  void raiseCapabilities();

  /**
   * @brief Drops all capabilities, optionally keeping some.
   * @param keep_caps Vector of capabilities to retain.
   */
  void dropCapabilities(const std::vector<cap_value_t> &keep_caps = {});
#endif
#ifdef VOIX_WITH_SECCOMP
  /**
   * @brief Applies a Seccomp blacklist to restrict dangerous system calls.
   */
  void applySeccompBlacklist() const;
  /**
   * @brief Applies a default-deny allowlist.
   *
   * Every syscall is killed unless it is part of the built-in process-runtime
   * baseline or named in @p extra_syscalls. The baseline includes
   * `execve`/`execveat` so the target can start at all; extend it with
   * `security.profiles.<name>.seccomp_allow` for the syscalls a specific
   * command needs.
   *
   * @param extra_syscalls Additional syscall names from the profile.
   */
  void applySeccompAllowlist(const std::vector<std::string> &extra_syscalls) const;
  /**
   * @brief The built-in allowlist baseline.
   *
   * Exposed so tests can assert the invariants that make allowlist mode
   * usable at all (notably that `execve`/`execveat` are present).
   */
  static std::span<const std::string_view> seccomp_allowlist_baseline();
#endif

  /**
   * @brief Checks that every name resolves to a syscall on this architecture.
   *
   * Used by `--check-config` so a typo in `seccomp_allow` is reported at
   * configuration time instead of killing the target at exec time. Returns an
   * empty string when every name is known, or a message naming the first
   * unknown entry. Always succeeds in builds without seccomp support.
   *
   * @param names Syscall names from the profile.
   * @return Empty on success, otherwise a user-facing error message.
   */
  static std::string validate_syscall_names(const std::vector<std::string> &names);

  std::shared_ptr<IIdentity> identity;
};

} // namespace Voix

#endif // SECURITY_H
