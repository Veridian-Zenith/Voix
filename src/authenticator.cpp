#include "authenticator.h"
#include "security.h"
#include "rule.h"
#include "pam_utils.h"
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <utility>

#ifndef NGROUPS_MAX
#define NGROUPS_MAX 32
#endif

namespace Voix {

Authenticator::Authenticator(std::shared_ptr<Security> security,
                             bool non_interactive)
    : security_(std::move(security)), non_interactive_(non_interactive) {}

bool Authenticator::authenticate(const std::optional<Rule>& rule) const {
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

  pam_handle_t *pamh = nullptr;
  struct pam_conv conv = {
      pam_conversation,
      nullptr
  };

  int pam_result = pam_start("voix", current_user.c_str(), &conv, &pamh);
  if (pam_result != PAM_SUCCESS) {
    std::cerr << "PAM initialization failed: "
              << pam_strerror(nullptr, pam_result) << '\n';
    return false;
  }

  pam_result = pam_authenticate(pamh, 0);
  bool auth_success = (pam_result == PAM_SUCCESS);

  if (!auth_success) {
    std::cerr << "Authentication failed: " << pam_strerror(pamh, pam_result)
              << '\n';
    security_->logEvent("PAM authentication failed", current_user);
  } else {
    pam_result = pam_acct_mgmt(pamh, 0);
    auth_success = (pam_result == PAM_SUCCESS);
    if (!auth_success) {
      std::cerr << "Account validation failed: "
                << pam_strerror(pamh, pam_result) << '\n';
    }
  }

  pam_end(pamh, pam_result);

  if (auth_success) {
    security_->logEvent("PAM authentication successful", current_user);
  }

  return auth_success;
}

} // namespace Voix
