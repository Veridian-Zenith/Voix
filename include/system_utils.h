/**
 * @file system_utils.h
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

#include <string_view>
#include <vector>
#include <optional>
#include <sys/types.h>

namespace Voix {

class SystemUtils {
public:
    SystemUtils() = default;
    ~SystemUtils() = default;

    bool setUserCredentials(uid_t uid, gid_t gid) const;
    void setEnvironment(const std::vector<std::string>& env_vars) const;

    static std::optional<uid_t> getUidByName(std::string_view name);
    static std::optional<gid_t> getGidByName(std::string_view name);
};

} // namespace Voix

#endif // SYSTEM_UTILS_H
