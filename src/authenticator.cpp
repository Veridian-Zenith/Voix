/**
 * @file authenticator.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "authenticator.hpp"
#include "security.hpp"
#include "config.hpp"
#include "rule.hpp"
#include "ticket_store.hpp"
#include "pam_utils.hpp"
#include "system_utils.hpp"
#include "logger.hpp"
#include "audit.hpp"
#include <unistd.h>
#include <format>
#include <utility>
#include <security/pam_appl.h>

namespace Voix {

PamAuthenticator::PamAuthenticator(std::shared_ptr<Security> security,
                             const Config& config,
                             bool non_interactive)
    : security_(std::move(security)), config_(config), non_interactive_(non_interactive) {}

PamAuthenticator::~PamAuthenticator() {
    if (pamh_) {
        pam_end(pamh_, PAM_SUCCESS);
    }
}

void PamAuthenticator::clear_timestamp() {
    TicketStore tickets(config_.getSanctuary());
    const uid_t uid = getuid();
    tickets.clear_all_for_caller(uid);
    LOG_INFO(std::format("Cleared persisted authentication timestamps for uid {}",
                         uid));
}

CredentialMode select_credential_mode(bool nopass, bool caller_is_root,
                                      bool persist_rule, bool ticket_valid,
                                      bool non_interactive) {
  if (nopass || caller_is_root) {
    return CredentialMode::SkipTrusted;
  }
  // A valid ticket is a substitute for the interactive prompt. It must be
  // consulted before the -n rejection, otherwise persisted sessions would
  // never work non-interactively.
  if (persist_rule && ticket_valid) {
    return CredentialMode::UseTicket;
  }
  if (non_interactive) {
    return CredentialMode::RejectNonInteractive;
  }
  return CredentialMode::RequireInteractive;
}

namespace {

/// Validate the target account with a separate PAM handle. This checks
/// account state (expiry/lock policy); it does NOT verify credentials and
/// must never be treated as proof that the target's password was checked.
/// Returns std::nullopt on success, or a user-facing reason on failure.
std::optional<std::string> validate_target_account(std::string_view target_user) {
  struct pam_handle* target_pamh = nullptr;
  struct pam_conv conv = {pam_conversation, nullptr};

  const std::string target{target_user};
  int result = pam_start("voix", target.c_str(), &conv, &target_pamh);
  if (result != PAM_SUCCESS) {
    return std::format("PAM could not be initialized for target '{}': {}",
                       target, pam_strerror(nullptr, result));
  }

  result = pam_acct_mgmt(target_pamh, 0);
  if (result != PAM_SUCCESS) {
    std::string reason =
        std::format("target account '{}' is not usable: {}", target,
                    pam_strerror(target_pamh, result));
    pam_end(target_pamh, result);
    return reason;
  }

  pam_end(target_pamh, PAM_SUCCESS);
  return std::nullopt;
}

} // namespace

bool PamAuthenticator::authenticate(const std::optional<Rule>& rule,
                                    std::string_view target_user) {
  last_error_.clear();
  const std::string current_user = security_->getCurrentUser();
  const bool nopass = rule && (rule->options & Rule::NOPASS);
  const bool persist_rule = rule && (rule->options & Rule::PERSIST);
  const bool caller_is_root = current_user == "root";

  auto target_entry = lookup_passwd_by_name(target_user);
  if (!target_entry) {
    last_error_ = std::format("target user does not exist: {}", target_user);
    security_->logEvent(Audit::invalid_target, "target user does not exist",
                        current_user);
    return false;
  }

  const uid_t caller_uid = getuid();
  const uid_t target_uid = target_entry->uid;
  TicketStore tickets(config_.getSanctuary());
  const bool ticket_valid =
      persist_rule && tickets.valid(caller_uid, target_uid);
  const CredentialMode mode =
      select_credential_mode(nopass, caller_is_root, persist_rule,
                             ticket_valid, non_interactive_);

  if (mode == CredentialMode::RejectNonInteractive) {
    last_error_ = "a credential check is required, but non-interactive mode "
                  "(-n) forbids prompting and no valid persisted ticket exists";
    return false;
  }

  auto fail = [this, &current_user](int pam_result, std::string_view what) {
      last_error_ = std::format("{}: {}", what, pam_strerror(pamh_, pam_result));
      security_->logEvent(Audit::authentication_failed, what, current_user);
      pam_end(pamh_, pam_result);
      pamh_ = nullptr;
  };

  if (pamh_) {
      pam_end(pamh_, PAM_SUCCESS);
      pamh_ = nullptr;
  }

  struct pam_conv conv = {
      pam_conversation,
      nullptr
  };

  int pam_result = pam_start("voix", current_user.c_str(), &conv, &pamh_);
  if (pam_result != PAM_SUCCESS) {
    last_error_ = std::format("PAM could not be initialized: {}",
                              pam_strerror(nullptr, pam_result));
    security_->logEvent(Audit::authentication_failed, last_error_,
                        current_user);
    return false;
  }

  bool credential_verified = false;
  if (mode == CredentialMode::RequireInteractive) {
    pam_result = pam_authenticate(pamh_, 0);
    if (pam_result != PAM_SUCCESS) {
      fail(pam_result, "PAM authentication failed");
      return false;
    }
    credential_verified = true;
  } else if (mode == CredentialMode::UseTicket) {
    LOG_INFO(std::format("Using persisted authentication timestamp for "
                         "caller {} target {}",
                         caller_uid, target_uid));
  } else {
    LOG_INFO("Skipping credential check (trust/nopass or root caller)");
  }

  // Caller account validation always runs: expired or disabled invoking
  // accounts must not execute commands even under trust/nopass rules.
  pam_result = pam_acct_mgmt(pamh_, 0);
  if (pam_result != PAM_SUCCESS) {
    fail(pam_result, "caller account validation failed");
    return false;
  }

  // Validate the target account separately. This is account-state validation,
  // not credential verification; only a successful pam_authenticate() above
  // can set credential_verified.
  if (auto target_error = validate_target_account(target_user)) {
    last_error_ = *target_error;
    security_->logEvent(Audit::account_validation_failed, *target_error,
                        current_user);
    if (pamh_) {
      pam_end(pamh_, PAM_AUTH_ERR);
      pamh_ = nullptr;
    }
    return false;
  }

  // Only a real credential verification may mint a persisted ticket. A
  // trust/nopass/root skip or a reused ticket must not bootstrap or refresh
  // one.
  if (persist_rule && credential_verified) {
    if (tickets.record(caller_uid, target_uid)) {
      LOG_INFO(std::format("Recorded persisted authentication timestamp for "
                           "caller {} target {}",
                           caller_uid, target_uid));
    } else {
      LOG_WARN("Failed to record persisted authentication timestamp");
    }
  }

  security_->logEvent(Audit::authentication_ok, "authentication successful",
                      current_user);
  return true;
}

bool PamAuthenticator::openSession() {
    last_error_.clear();
    if (!pamh_) return true;

    int result = pam_setcred(pamh_, PAM_ESTABLISH_CRED);
    if (result != PAM_SUCCESS) {
        last_error_ = std::format("could not establish PAM credentials: {}",
                                  pam_strerror(pamh_, result));
        return false;
    }

    result = pam_open_session(pamh_, 0);
    if (result != PAM_SUCCESS) {
        last_error_ = std::format("could not open PAM session: {}",
                                  pam_strerror(pamh_, result));
        return false;
    }
    return true;
}

void PamAuthenticator::closeSession() {
    if (pamh_) {
        int result = pam_close_session(pamh_, 0);
        if (result != PAM_SUCCESS) {
            LOG_WARN(std::format("Failed to close PAM session: {}",
                     pam_strerror(pamh_, result)));
        }
        result = pam_setcred(pamh_, PAM_DELETE_CRED);
        if (result != PAM_SUCCESS) {
            LOG_WARN(std::format("Failed to delete PAM credentials: {}",
                     pam_strerror(pamh_, result)));
        }
        pam_end(pamh_, result);
        pamh_ = nullptr;
    }
}

} // namespace Voix
