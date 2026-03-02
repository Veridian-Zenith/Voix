/**
 * @file voix.cpp
 * @brief Enhanced Voix implementation with OpenDoas integration
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed
 * under OSL v3.
 */

#include "voix.h"
#include "config.h"
#include "lua_config.h"
#include "security.h"
#include "utils.h"
#include <algorithm>
#include <cstring>
#include <grp.h>
#include <iostream>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <sys/types.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

namespace Voix {

// PAM conversation function for password prompting
static int pam_conversation(int num_msg, const struct pam_message **msg,
                            struct pam_response **resp, void *appdata_ptr) {
  (void)appdata_ptr; // Unused parameter
  struct pam_response *response = nullptr;

  response =
      (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
  if (!response) {
    return PAM_CONV_ERR;
  }

  for (int i = 0; i < num_msg; i++) {
    switch (msg[i]->msg_style) {
    case PAM_PROMPT_ECHO_OFF: {
      // Password prompt - disable echo
      struct termios old_term, new_term;
      tcgetattr(STDIN_FILENO, &old_term);
      new_term = old_term;
      new_term.c_lflag &= ~ECHO;
      tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

      std::cout << msg[i]->msg;
      std::cout.flush();

      char password[512] = {0};
      std::cin.getline(password, sizeof(password));

      tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
      std::cout << std::endl;

      response[i].resp = strdup(password);
      memset(password, 0, sizeof(password));
      response[i].resp_retcode = 0;
      break;
    }
    case PAM_PROMPT_ECHO_ON:
      // Username - echo enabled
      std::cout << msg[i]->msg;
      std::cout.flush();
      {
        std::string input;
        std::getline(std::cin, input);
        response[i].resp = strdup(input.c_str());
        response[i].resp_retcode = 0;
      }
      break;
    case PAM_ERROR_MSG:
      std::cerr << "PAM Error: " << msg[i]->msg << std::endl;
      response[i].resp_retcode = 0;
      break;
    case PAM_TEXT_INFO:
      std::cout << msg[i]->msg << std::endl;
      response[i].resp_retcode = 0;
      break;
    default:
      free(response);
      return PAM_CONV_ERR;
    }
  }

  *resp = response;
  return PAM_SUCCESS;
}

} // namespace Voix

namespace Voix {

Voix::Voix(const std::string &config_path, bool non_interactive,
           bool clear_timestamp)
    : config_(std::make_unique<Config>()),
      security_(std::make_unique<Security>()),
      utils_(std::make_unique<Utils>()),
      lua_config_(std::make_unique<LuaConfig>()), config_path_(config_path),
      non_interactive_(non_interactive), clear_timestamp_(clear_timestamp) {

  // Load configuration
  if (!loadConfig(config_path_)) {
    throw std::runtime_error("Failed to load configuration");
  }

  // Handle timestamp clearing if requested
  if (clear_timestamp_) {
    // In a full implementation, this would clear persist authentication
    // For now, just log the action
    security_->logEvent("Timestamp cleared (persist authentication reset)",
                        "system");
  }
}

Voix::~Voix() = default;

int Voix::execute(const std::string &command,
                  const std::vector<std::string> &args,
                  const std::string &user) {

  std::string current_user = security_->getCurrentUser();

  // Security logging
  security_->logEvent("Command execution requested: " + command, current_user);
  syslog(LOG_AUTHPRIV | LOG_INFO, "Command execution requested: %s as %s",
         command.c_str(), user.c_str());

  // First authenticate the user
  if (!authenticate()) {
    security_->logEvent("Authentication failed for user: " + current_user,
                        current_user);
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "Authentication failed for user: %s",
           current_user.c_str());
    return 1;
  }

  // Validate user permissions
  if (!security_->validateUser(current_user)) {
    security_->logEvent("Unauthorized user attempt: " + current_user,
                        current_user);
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "Unauthorized user attempt: %s",
           current_user.c_str());
    return 1;
  }

  // Validate command using enhanced rules
  uid_t target_uid;
  struct passwd *pw = getpwnam(user.c_str());
  if (!pw) {
    syslog(LOG_AUTHPRIV | LOG_ERR, "Invalid target user: %s", user.c_str());
    return 1;
  }
  target_uid = pw->pw_uid;

  if (!permit(command, args, target_uid)) {
    security_->logEvent("Command not permitted: " + command, current_user);
    syslog(LOG_AUTHPRIV | LOG_NOTICE, "Command not permitted: %s as %s",
           command.c_str(), user.c_str());
    return 1;
  }

  // Execute the command with enhanced security
  return utils_->executeCommand(command, args, user);
}

bool Voix::isAllowed() const {
  std::string current_user = security_->getCurrentUser();

  // Check if user exists in system
  if (!security_->validateUser(current_user)) {
    return false;
  }

  // Check Lua configuration first
  if (lua_config_->isUserAllowed(current_user)) {
    return true;
  }

  // Fallback to traditional admin groups
  struct passwd *pw = getpwnam(current_user.c_str());
  if (!pw)
    return false;

  gid_t groups[NGROUPS_MAX + 1];
  int ngroups = getgroups(NGROUPS_MAX, groups);
  if (ngroups == -1)
    return false;
  groups[ngroups++] = getgid();

  // Check if user is root or in wheel group
  if (pw->pw_uid == 0)
    return true;

  for (int i = 0; i < ngroups; i++) {
    struct group *gr = getgrgid(groups[i]);
    if (gr && strcmp(gr->gr_name, "wheel") == 0) {
      return true;
    }
  }

  return false;
}

bool Voix::validateCommand(const std::string &command,
                           const std::vector<std::string> &args) const {
  std::string current_user = security_->getCurrentUser();

  // First check basic security validation
  if (!security_->validateCommand(command, args)) {
    return false;
  }

  // Check Lua configuration rules
  if (lua_config_->validateCommand(current_user, command, args)) {
    return true;
  }

  return false;
}

bool Voix::authenticate() const {
  std::string current_user = security_->getCurrentUser();
  pam_handle_t *pamh = nullptr;
  int pam_result = 0;

  // Root is always authenticated
  if (current_user == "root") {
    return true;
  }

  // Check if user is in wheel group - if yes, require password through PAM
  struct passwd *pw = getpwnam(current_user.c_str());
  if (!pw) {
    return false;
  }

  gid_t groups[NGROUPS_MAX + 1];
  int ngroups = getgroups(NGROUPS_MAX, groups);
  if (ngroups == -1)
    return false;
  groups[ngroups++] = getgid();

  bool in_wheel = false;
  for (int i = 0; i < ngroups; i++) {
    struct group *gr = getgrgid(groups[i]);
    if (gr && strcmp(gr->gr_name, "wheel") == 0) {
      in_wheel = true;
      break;
    }
  }

  // If not in wheel group, check rules
  if (!in_wheel) {
    return lua_config_->validateCommand(current_user, "*", {});
  }

  // Wheel group members need PAM authentication
  if (non_interactive_) {
    return false; // Cannot authenticate interactively in non-interactive mode
  }

  // Initialize PAM conversation
  struct pam_conv conv = {
      pam_conversation,
      nullptr // appdata_ptr
  };

  // Start PAM session
  pam_result = pam_start("voix", current_user.c_str(), &conv, &pamh);
  if (pam_result != PAM_SUCCESS) {
    std::cerr << "PAM initialization failed: "
              << pam_strerror(nullptr, pam_result) << std::endl;
    return false;
  }

  // Authenticate user
  pam_result = pam_authenticate(pamh, 0);
  bool auth_success = (pam_result == PAM_SUCCESS);

  if (!auth_success) {
    std::cerr << "Authentication failed: " << pam_strerror(pamh, pam_result)
              << std::endl;
    security_->logEvent("PAM authentication failed", current_user);
  }

  // Account management
  if (auth_success) {
    pam_result = pam_acct_mgmt(pamh, 0);
    auth_success = (pam_result == PAM_SUCCESS);
    if (!auth_success) {
      std::cerr << "Account validation failed: "
                << pam_strerror(pamh, pam_result) << std::endl;
    }
  }

  // Clean up PAM
  pam_end(pamh, pam_result);

  if (auth_success) {
    security_->logEvent("PAM authentication successful", current_user);
  }

  return auth_success;
}

std::string Voix::getCurrentUser() const { return security_->getCurrentUser(); }

bool Voix::loadConfig(const std::string &config_path) {
  // Try Lua config first
  if (!lua_config_->loadConfig(config_path)) {
    // Fallback to traditional config
    // config_->load(config_path);
    return false;
  }
  return true;
}

// OpenDoas-style rule matching
bool Voix::matchRule(const Rule &rule, uid_t uid, gid_t *groups, int ngroups,
                     uid_t target_uid, const std::string &command,
                     const std::vector<std::string> &args) const {

  // Check ident (user/group)
  if (!rule.ident.empty()) {
    if (rule.ident[0] == ':') {
      // Group match
      gid_t rgid;
      char *endptr;
      rgid = strtol(rule.ident.c_str() + 1, &endptr, 10);
      if (*endptr != '\0') {
        // Group name
        struct group *gr = getgrnam(rule.ident.c_str() + 1);
        if (gr)
          rgid = gr->gr_gid;
      }

      bool group_found = false;
      for (int i = 0; i < ngroups; i++) {
        if (rgid == groups[i]) {
          group_found = true;
          break;
        }
      }
      if (!group_found)
        return false;
    } else {
      // User match
      struct passwd *pw = getpwnam(rule.ident.c_str());
      if (pw) {
        if (pw->pw_uid != uid)
          return false;
      } else {
        // Numeric UID
        uid_t rule_uid =
            static_cast<uid_t>(strtol(rule.ident.c_str(), nullptr, 10));
        if (rule_uid != uid)
          return false;
      }
    }
  }

  // Check target user
  if (!rule.target.empty()) {
    struct passwd *pw = getpwnam(rule.target.c_str());
    if (pw) {
      if (pw->pw_uid != target_uid)
        return false;
    } else {
      // Numeric UID
      uid_t rule_uid =
          static_cast<uid_t>(strtol(rule.target.c_str(), nullptr, 10));
      if (rule_uid != target_uid)
        return false;
    }
  }

  // Check command
  if (!rule.cmd.empty()) {
    if (rule.cmd != command)
      return false;

    // Check arguments if specified
    if (!rule.cmdargs.empty()) {
      if (args.size() != rule.cmdargs.size())
        return false;

      for (size_t i = 0; i < args.size(); i++) {
        if (rule.cmdargs[i] != args[i])
          return false;
      }
    }
  }

  return true;
}

// Enhanced permission checking with OpenDoas-style rules
bool Voix::permit(const std::string &command,
                  const std::vector<std::string> &args,
                  uid_t target_uid) const {
  std::string current_user = getCurrentUser();
  struct passwd *pw = getpwnam(current_user.c_str());
  if (!pw)
    return false;

  uid_t uid = pw->pw_uid;
  gid_t groups[NGROUPS_MAX + 1];
  int ngroups = getgroups(NGROUPS_MAX, groups);
  if (ngroups == -1)
    return false;
  groups[ngroups++] = getgid();

  // Get rules from Lua config
  auto rules = lua_config_->getRules();

  // Check each rule
  for (const auto &rule : rules) {
    if (matchRule(rule, uid, groups, ngroups, target_uid, command, args)) {
      return rule.action == Rule::PERMIT;
    }
  }

  // Default deny if no rules match
  return false;
}

} // namespace Voix
