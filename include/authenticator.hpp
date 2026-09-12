/**
 * @file authenticator.h
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <memory>
#include <optional>
#include <string>

// Forward declaration of pam struct
struct pam_handle;

namespace Voix {

class Security;
class Rule;
class Config;

/**
 * @brief Interface for user authentication.
 */
class IAuthenticator {
public:
    virtual ~IAuthenticator() = default;
    /**
     * @brief Authenticates the user.
     *
     * Account validation (pam_acct_mgmt) is always performed, even when the
     * rule carries a trust/nopass option or a fresh persisted timestamp —
     * only the interactive credential check may be skipped.
     *
     * When the target user has no password (locked/service account), the
     * credential check is also skipped regardless of the rule's trust setting.
     *
     * @param rule Optional rule to consider during authentication.
     * @param target_user The target user being switched to (for password check).
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

private:
    std::shared_ptr<Security> security_;
    const Config& config_;
    bool non_interactive_;
    struct pam_handle* pamh_ = nullptr;
};

} // namespace Voix

#endif // AUTHENTICATOR_H
