/**
 * @file audit.hpp
 * @brief Stable identifiers for security audit events.
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef AUDIT_H
#define AUDIT_H

#include <string_view>

namespace Voix::Audit {

/// Stable `code` values written by Security::logEvent(). Treat these as part
/// of the audit-log interface: add new values, but do not rename existing
/// ones. Records are formatted as `[user] [code] human-readable detail`.
inline constexpr std::string_view command_requested = "command.requested";
inline constexpr std::string_view command_rejected = "command.rejected";
inline constexpr std::string_view command_blocked = "command.blocked";
inline constexpr std::string_view command_denied = "command.denied";
inline constexpr std::string_view command_executed = "command.executed";
inline constexpr std::string_view command_withheld = "command.withheld";
inline constexpr std::string_view invalid_target = "auth.invalid-target";
inline constexpr std::string_view authentication_ok = "auth.ok";
inline constexpr std::string_view authentication_failed = "auth.failed";
inline constexpr std::string_view account_validation_failed =
    "auth.account-failed";
inline constexpr std::string_view session_open_failed = "session.open-failed";
inline constexpr std::string_view session_closed = "session.closed";

} // namespace Voix::Audit

#endif // AUDIT_H
