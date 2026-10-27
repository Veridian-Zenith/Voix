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
 * @brief Stores caller/target authentication timestamps under the configured
 *        sanctuary directory (<sanctuary>/timestamp/<caller>-<target>).
 *
 * Tickets are scoped to both the invoking UID and the target UID, so a
 * password verified for one target cannot authorize a switch to another.
 * Files are created/read with strict TOCTOU protection (O_NOFOLLOW,
 * owner == effective UID, mode 0600) via FileUtils. All failures are
 * fail-safe: a missing or unreadable ticket simply means "no persisted
 * authentication" and the normal password flow proceeds.
 */
class TicketStore {
public:
    explicit TicketStore(std::string_view sanctuary);

    /**
     * @brief Checks whether a fresh (non-expired) ticket exists for the
     *        caller/target pair.
     */
    bool valid(uid_t caller_uid, uid_t target_uid,
               std::chrono::minutes ttl = k_persist_ttl) const;

    /**
     * @brief Records/refreshes the timestamp for the caller/target pair.
     * @return True on success; false means the next run will require proof.
     */
    bool record(uid_t caller_uid, uid_t target_uid) const;

    /**
     * @brief Removes the timestamp for one caller/target pair.
     */
    void clear(uid_t caller_uid, uid_t target_uid) const;

    /**
     * @brief Removes every timestamp belonging to the caller (-k behavior).
     */
    void clear_all_for_caller(uid_t caller_uid) const;

private:
    std::filesystem::path path_for(uid_t caller_uid, uid_t target_uid) const;

    std::filesystem::path dir_;
};

} // namespace Voix

#endif // TICKET_STORE_H
