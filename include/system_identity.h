/**
 * @file system_identity.h
 * @brief Interface for system identity operations to allow mocking in tests.
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef SYSTEM_IDENTITY_H
#define SYSTEM_IDENTITY_H

#include <string>
#include <vector>
#include <sys/types.h>
#include <optional>

namespace Voix {

struct UserIdentity {
    std::string username;
    uid_t uid;
    gid_t gid;
    std::vector<gid_t> groups;
    std::string home_dir;
    std::string shell;
};

class IIdentity {
public:
    virtual ~IIdentity() = default;
    virtual std::optional<UserIdentity> getUserByName(const std::string& username) const = 0;
    virtual std::optional<UserIdentity> getUserByUid(uid_t uid) const = 0;
    virtual std::string getCurrentUsername() const = 0;
    virtual uid_t getCurrentUid() const = 0;
    virtual std::vector<gid_t> getCurrentGroups() const = 0;
};

class SystemIdentity : public IIdentity {
public:
    std::optional<UserIdentity> getUserByName(const std::string& username) const override;
    std::optional<UserIdentity> getUserByUid(uid_t uid) const override;
    std::string getCurrentUsername() const override;
    uid_t getCurrentUid() const override;
    std::vector<gid_t> getCurrentGroups() const override;
};

} // namespace Voix

#endif // SYSTEM_IDENTITY_H
