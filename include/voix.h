/**
 * @file voix.h
 * @brief Enhanced Voix header with OpenDoas integration
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef VOIX_H
#define VOIX_H

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <memory>

namespace Voix {

class Config;
class Security;
class Command;
class Authenticator;
class PermissionChecker;

class Voix {
public:
    Voix(std::string_view config_path = "/etc/voix.conf",
         bool non_interactive = false, bool clear_timestamp = false);
    ~Voix();

    int execute(std::string_view command,
                const std::vector<std::string>& args = {},
                std::string_view user = "root");

private:
    std::shared_ptr<Config> config_;
    std::shared_ptr<Security> security_;
    std::unique_ptr<Authenticator> authenticator_;
    std::unique_ptr<PermissionChecker> permission_checker_;
    std::unique_ptr<Command> command_;
    bool clear_timestamp_;
};

} // namespace Voix

#endif // VOIX_H
