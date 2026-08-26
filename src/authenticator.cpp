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
#include "logger.hpp"
#include <unistd.h>
#include <format>
#include <print>
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
    tickets.clear(uid);
    LOG_INFO(std::format("Cleared persisted authentication timestamp for uid {}", uid));
}

bool PamAuthenticator::authenticate(const std::optional<Rule>& rule) {
  std::string current_user = security_->getCurrentUser();
  const bool nopass = rule && (rule->options & Rule::NOPASS);
  const bool persist_rule = rule && (rule->options & Rule::PERSIST);

  // Interactive credential check can be skipped for root, trusted rules and
  // fresh persisted timestamps. Account validation below always runs.
  bool skip_credential_check = nopass;
  if (!skip_credential_check && current_user == "root") {
    skip_credential_check = true;
  }

  if (!skip_credential_check && non_interactive_) {
    return false;
  }

  TicketStore tickets(config_.getSanctuary());
  const uid_t caller_uid = getuid();

  if (!skip_credential_check && persist_rule && tickets.valid(caller_uid)) {
    LOG_INFO("Using persisted authentication timestamp");
    skip_credential_check = true;
  }

  auto fail = [this](int pam_result, std::string_view what) {
      std::println(stderr, "{}: {}", what, pam_strerror(pamh_, pam_result));
      security_->logEvent(std::format("{} failed", what), "user");
      pam_end(pamh_, pam_result);
      pamh_ = nullptr;
  };

  if (!skip_credential_check) {
    if (pamh_) {
        pam_end(pamh_, 0);
        pamh_ = nullptr;
    }

    struct pam_conv conv = {
        pam_conversation,
        nullptr
    };

    int pam_result = pam_start("voix", current_user.c_str(), &conv, &pamh_);
    if (pam_result != PAM_SUCCESS) {
      std::println(stderr, "PAM initialization failed: {}",
                   pam_strerror(nullptr, pam_result));
      return false;
    }

    pam_result = pam_authenticate(pamh_, 0);
    if (pam_result != PAM_SUCCESS) {
      security_->logEvent("PAM authentication failed", current_user);
      fail(pam_result, "Authentication failed");
      return false;
    }
  } else if (!pamh_) {
    // No credential check needed, but the PAM handle is still required for
    // account validation and session management.
    struct pam_conv conv = {
        pam_conversation,
        nullptr
    };
    int pam_result = pam_start("voix", current_user.c_str(), &conv, &pamh_);
    if (pam_result != PAM_SUCCESS) {
      std::println(stderr, "PAM initialization failed: {}",
                   pam_strerror(nullptr, pam_result));
      return false;
    }
  }

  // Account validation always runs: expired or disabled accounts must not
  // execute commands even under trust/nopass rules.
  int pam_result = pam_acct_mgmt(pamh_, 0);
  if (pam_result != PAM_SUCCESS) {
    fail(pam_result, "Account validation failed");
    return false;
  }

  if (persist_rule) {
    if (tickets.record(caller_uid)) {
      LOG_INFO("Recorded persisted authentication timestamp");
    } else {
      LOG_WARN("Failed to record persisted authentication timestamp");
    }
  }

  security_->logEvent("PAM authentication successful", current_user);
  return true;
}

bool PamAuthenticator::openSession() {
    if (!pamh_) return true;

    int result = pam_setcred(pamh_, PAM_ESTABLISH_CRED);
    if (result == PAM_SUCCESS) {
        result = pam_open_session(pamh_, 0);
        if (result != PAM_SUCCESS) {
            std::println(stderr, "Failed to open PAM session: {}", pam_strerror(pamh_, result));
            return false;
        }
        return true;
    } else {
        std::println(stderr, "Failed to set PAM credentials: {}", pam_strerror(pamh_, result));
    }
    return false;
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
