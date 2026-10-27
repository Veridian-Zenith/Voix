/**
 * @file ticket_store.cpp
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include "ticket_store.hpp"
#include "file_utils.hpp"
#include <chrono>
#include <cstdint>
#include <cstdlib>

namespace Voix {

TicketStore::TicketStore(std::string_view sanctuary)
    : dir_(std::filesystem::path(sanctuary) / "timestamp") {}

std::filesystem::path TicketStore::path_for(uid_t caller_uid,
                                            uid_t target_uid) const {
    return dir_ / (std::to_string(caller_uid) + "-" +
                   std::to_string(target_uid));
}

bool TicketStore::valid(uid_t caller_uid, uid_t target_uid,
                        std::chrono::minutes ttl) const {
    FileUtils fu;
    auto content = fu.read_file_secure(path_for(caller_uid, target_uid));
    if (!content || content->empty()) return false;

    std::uint64_t epoch = 0;
    char* end = nullptr;
    epoch = std::strtoull(content->c_str(), &end, 10);
    if (end == content->c_str()) return false;  // No digits parsed

    const auto written = std::chrono::seconds(epoch);
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch());
    if (written > now) return false;  // Future timestamp: clock skew/tampering
    return (now - written) <= ttl;
}

bool TicketStore::record(uid_t caller_uid, uid_t target_uid) const {
    FileUtils fu;
    if (!fu.ensure_private_directory(dir_)) return false;

    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch());
    return fu.write_file_secure(path_for(caller_uid, target_uid),
                                std::to_string(now.count()))
        .has_value();
}

void TicketStore::clear(uid_t caller_uid, uid_t target_uid) const {
    std::error_code ec;
    std::filesystem::remove(path_for(caller_uid, target_uid), ec);
}

void TicketStore::clear_all_for_caller(uid_t caller_uid) const {
    std::error_code ec;
    if (!std::filesystem::is_directory(dir_, ec)) return;

    const std::string prefix = std::to_string(caller_uid) + "-";
    for (std::filesystem::directory_iterator it(dir_, ec), end;
         !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        if (name.starts_with(prefix)) {
            std::error_code remove_ec;
            std::filesystem::remove(it->path(), remove_ec);
        }
    }
}

} // namespace Voix
