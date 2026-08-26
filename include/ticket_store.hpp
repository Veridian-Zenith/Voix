/**
 * @file ticket_store.h
 * @brief Persisted authentication timestamp storage ("persist" option).
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#ifndef TICKET_STORE_H
#define TICKET_STORE_H

#include <chrono>
#include <filesystem>
#include <string>
#include <sys/types.h>

namespace Voix {

/// How long a persisted authentication timestamp remains valid.
constexpr std::chrono::minutes k_persist_ttl{15};

/**
 * @brief Stores per-UID authentication timestamps under the configured
 *        sanctuary directory (<sanctuary>/timestamp/<uid>).
 *
 * Files are created/read with strict TOCTOU protection (O_NOFOLLOW,
 * owner == effective UID, mode 0600) via FileUtils. All failures are
 * fail-safe: a missing or unreadable ticket simply means "no persisted
 * authentication" and the normal password flow proceeds.
 */
class TicketStore {
public:
    explicit TicketStore(std::string_view sanctuary);

    /**
     * @brief Checks whether a fresh (non-expired) ticket exists for uid.
     */
    bool valid(uid_t uid, std::chrono::minutes ttl = k_persist_ttl) const;

    /**
     * @brief Records/refreshes the timestamp for uid.
     * @return True on success; false means the next run will require proof.
     */
    bool record(uid_t uid) const;

    /**
     * @brief Removes any existing timestamp for uid (-k behavior).
     */
    void clear(uid_t uid) const;

private:
    std::filesystem::path path_for(uid_t uid) const;

    std::filesystem::path dir_;
};

} // namespace Voix

#endif // TICKET_STORE_H
