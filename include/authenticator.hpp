/**
 * @file authenticator.h
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

// Forward declaration of pam struct
struct pam_handle;

namespace Voix {

class Security;
class Rule;
class Config;

/**
 * @brief How the credential check for one invocation should be handled.
 *
 * The order is security-significant: a valid persisted ticket is consulted
 * before non-interactive mode rejects the invocation, so `-n` can reuse a
 * ticket but can never prompt. Trust/nopass and root callers skip the
 * credential check entirely; neither path may mint a persist ticket.
 */
enum class CredentialMode : std::uint8_t {
    SkipTrusted,
    UseTicket,
    RequireInteractive,
    RejectNonInteractive,
};

CredentialMode select_credential_mode(bool nopass, bool caller_is_root,
                                      bool persist_rule, bool ticket_valid,
                                      bool non_interactive);

/**
 * @brief Interface for user authentication.
 */
class IAuthenticator {
public:
    virtual ~IAuthenticator() = default;
    /**
     * @brief Authenticates the user.
     *
     * Account validation (pam_acct_mgmt) is always performed for both the
     * caller and the target account, even when the rule carries a
     * trust/nopass option or a fresh persisted timestamp — only the
     * interactive credential check may be skipped. Target account validation
     * is not credential verification.
     *
     * @param rule Optional rule to consider during authentication.
     * @param target_user The target user being switched to (for account
     *        validation and ticket scoping).
     * @return True if authentication succeeded, false otherwise.
     */
    virtual bool authenticate(const std::optional<Rule>& rule,
                              std::string_view target_user = "root") = 0;
    /**
     * @brief Opens a session for the authenticated user.
     * @return True if session was opened successfully, false otherwise.
     */
    virtual bool openSession() = 0;
    /**
     * @brief Closes the current session.
     */
    virtual void closeSession() = 0;
    /**
     * @brief Invalidates any persisted authentication timestamp (-k).
     */
    virtual void clear_timestamp() = 0;
    /**
     * @brief Returns the reason the most recent authenticate()/openSession()
     *        call failed, for user-facing diagnostics. Empty on success or
     *        when the implementation has no detail.
     */
    virtual std::string_view last_error() const { return {}; }
};

/**
 * @brief PAM-based authentication implementation.
 */
class PamAuthenticator : public IAuthenticator {
public:
    /**
     * @brief Constructor for PamAuthenticator.
     * @param security Pointer to the security manager.
     * @param config Loaded configuration (sanctuary for timestamp storage).
     * @param non_interactive Whether authentication should be non-interactive.
     */
    PamAuthenticator(std::shared_ptr<Security> security,
                     const Config& config,
                     bool non_interactive);
    /**
     * @brief Destructor for PamAuthenticator.
     */
    ~PamAuthenticator() override;

    bool authenticate(const std::optional<Rule>& rule,
                      std::string_view target_user = "root") override;
    bool openSession() override;
    void closeSession() override;
    void clear_timestamp() override;
    std::string_view last_error() const override { return last_error_; }

private:
    std::shared_ptr<Security> security_;
    const Config& config_;
    bool non_interactive_;
    struct pam_handle* pamh_ = nullptr;
    std::string last_error_;
};

} // namespace Voix

#endif // AUTHENTICATOR_H
