/**
 * @file exit_code.hpp
 * @brief Stable process exit codes and the exception type that carries them.
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef EXIT_CODE_H
#define EXIT_CODE_H

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace Voix {

/**
 * @brief Process exit codes returned by Voix itself.
 *
 * Values follow sysexits(3) where an appropriate code exists. A command's own
 * exit status is propagated verbatim, so these values can also be produced by
 * the executed program; they are documented as Voix's meaning when Voix
 * returns before or instead of executing a command.
 */
enum class ExitCode : std::uint8_t {
  Success = 0,
  /// Generic runtime failure. Authentication failures use this value to match
  /// the sudo/doas convention.
  Failure = 1,
  /// Invalid command line (unknown flag, missing command, bad -u value).
  Usage = 64, // EX_USAGE
  /// Internal invariant failure (fork/waitpid, signal setup).
  Software = 70, // EX_SOFTWARE
  /// Policy denied the request, an unsafe executable was refused, or a hard
  /// safety gate blocked it.
  NotPermitted = 77, // EX_NOPERM
  /// Configuration could not be loaded, parsed, or validated.
  Config = 78, // EX_CONFIG
  /// The command was found but could not be executed.
  NoExec = 126,
  /// The command could not be found.
  NotFound = 127,
};

constexpr int exit_status(ExitCode code) noexcept {
  return static_cast<int>(code);
}

constexpr std::string_view exit_code_name(ExitCode code) noexcept {
  switch (code) {
    case ExitCode::Success:
      return "success";
    case ExitCode::Failure:
      return "failure";
    case ExitCode::Usage:
      return "usage";
    case ExitCode::Software:
      return "software";
    case ExitCode::NotPermitted:
      return "not-permitted";
    case ExitCode::Config:
      return "config";
    case ExitCode::NoExec:
      return "no-exec";
    case ExitCode::NotFound:
      return "not-found";
  }
  return "failure";
}

/**
 * @brief Exception that carries a stable exit code and an optional hint.
 *
 * Hints are user-facing remediation text. They are printed after the error
 * message and never included in the audit record's machine-readable prefix.
 */
class VoixError : public std::runtime_error {
public:
  // The two strings are named at every call site (`message`, `hint`) and the
  // constructor is only used for `throw VoixError(...)`; a strong type would
  // add ceremony without making the intent clearer.
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  VoixError(ExitCode code, const std::string &message, std::string hint = {})
      : std::runtime_error(message),
        code_(code),
        hint_(std::move(hint)) {}

  ExitCode code() const noexcept { return code_; }
  const std::string &hint() const noexcept { return hint_; }

private:
  ExitCode code_;
  std::string hint_;
};

} // namespace Voix

#endif // EXIT_CODE_H
