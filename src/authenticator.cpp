/**
 * @file authenticator.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "authenticator.h"
#include "security.h"
#include "rule.h"
#include "pam_utils.h"
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <cstring>
#include <print>
#include <utility>
#include <security/pam_appl.h>

#ifndef NGROUPS_MAX
#define NGROUPS_MAX 32
#endif

namespace Voix {

PamAuthenticator::PamAuthenticator(std::shared_ptr<Security> security,
                             bool non_interactive)
    : security_(std::move(security)), non_interactive_(non_interactive) {}

PamAuthenticator::~PamAuthenticator() {
    if (pamh_) {
        pam_end(pamh_, PAM_SUCCESS);
    }
}

bool PamAuthenticator::authenticate(const std::optional<Rule>& rule) {
  if (rule && (rule->options & Rule::NOPASS)) {
    return true;
  }

  std::string current_user = security_->getCurrentUser();
  if (current_user == "root") {
    return true;
  }

  if (non_interactive_) {
    return false;
  }

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
  bool auth_success = (pam_result == PAM_SUCCESS);

  if (!auth_success) {
    std::println(stderr, "Authentication failed: {}", pam_strerror(pamh_, pam_result));
    security_->logEvent("PAM authentication failed", current_user);
  } else {
    pam_result = pam_acct_mgmt(pamh_, 0);
    auth_success = (pam_result == PAM_SUCCESS);
    if (!auth_success) {
      std::println(stderr, "Account validation failed: {}",
                   pam_strerror(pamh_, pam_result));
    }
  }

  if (!auth_success) {
    pam_end(pamh_, pam_result);
    pamh_ = nullptr;
  } else {
    security_->logEvent("PAM authentication successful", current_user);
  }

  return auth_success;
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
        pam_close_session(pamh_, 0);
        pam_setcred(pamh_, PAM_DELETE_CRED);
    }
}

} // namespace Voix
