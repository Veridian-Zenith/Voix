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

class Authenticator {
public:
    Authenticator(std::shared_ptr<Security> security, bool non_interactive);
    ~Authenticator();

    bool authenticate(const std::optional<Rule>& rule);
    bool openSession();
    void closeSession();

private:
    std::shared_ptr<Security> security_;
    bool non_interactive_;
    struct pam_handle* pamh_ = nullptr;
};

} // namespace Voix

#endif // AUTHENTICATOR_H
