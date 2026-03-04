#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <memory>
#include <optional>
#include <string>

namespace Voix {

class Security;
class Rule;

class Authenticator {
public:
    Authenticator(std::shared_ptr<Security> security, bool non_interactive);
    ~Authenticator() = default;

    bool authenticate(const std::optional<Rule>& rule) const;

private:
    std::shared_ptr<Security> security_;
    bool non_interactive_;
};

} // namespace Voix

#endif // AUTHENTICATOR_H
