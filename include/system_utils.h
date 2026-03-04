#ifndef SYSTEM_UTILS_H
#define SYSTEM_UTILS_H

#include <string>
#include <vector>
#include <sys/types.h>

namespace Voix {

class SystemUtils {
public:
    SystemUtils() = default;
    ~SystemUtils() = default;

    bool setUserCredentials(uid_t uid, gid_t gid) const;
    void setEnvironment(const std::vector<std::string>& env_vars) const;
};

} // namespace Voix

#endif // SYSTEM_UTILS_H
