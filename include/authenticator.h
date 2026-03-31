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

class IAuthenticator {
public:
    virtual ~IAuthenticator() = default;
    virtual bool authenticate(const std::optional<Rule>& rule) = 0;
    virtual bool openSession() = 0;
    virtual void closeSession() = 0;
};

class PamAuthenticator : public IAuthenticator {
public:
    PamAuthenticator(std::shared_ptr<Security> security, bool non_interactive);
    ~PamAuthenticator() override;

    bool authenticate(const std::optional<Rule>& rule) override;
    bool openSession() override;
    void closeSession() override;

private:
    std::shared_ptr<Security> security_;
    bool non_interactive_;
    struct pam_handle* pamh_ = nullptr;
};

} // namespace Voix

#endif // AUTHENTICATOR_H
