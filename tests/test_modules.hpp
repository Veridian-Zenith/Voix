/**
 * @file test_modules.hpp
 * @brief Test module
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#pragma once

/**
 * @file test_modules.hpp
 * @brief Shared test fixtures and per-module registration declarations.
 * @copyright Copyright (C) 2026 Veridian Zenith
 */

#include "test_assert.hpp"
#include "../include/file_utils.hpp"
#include "../include/logger.hpp"
#include "../include/security.hpp"
#include "../include/config.hpp"
#include "../include/permission_checker.hpp"
#include "../include/system_identity.hpp"
#include "../include/command.hpp"
#include "../include/system_utils.hpp"
#include "../include/ticket_store.hpp"
#include <fstream>
#include <filesystem>
#include <memory>
#include <cstdlib>
#include <chrono>
#include <regex>

/// Detect a preload-based instrumentation library (for example CodeQL's
/// tracer). Such libraries interpose syscalls, so a default-deny seccomp
/// allowlist would kill the instrumentation rather than the program under
/// test. End-to-end allowlist tests are skipped in that case; the dedicated
/// Test Suite job runs them without instrumentation.
inline bool detect_syscall_instrumentation() {
    for (const char* name : {"LD_PRELOAD", "LD_AUDIT"}) {
        const char* value = std::getenv(name);
        if (value != nullptr && *value != '\0') {
            return true;
        }
    }
    return false;
}

/// Cached so tests that unset LD_PRELOAD in the parent process cannot hide
/// instrumentation that was present when the suite started. run_tests()
/// primes the cache before any test runs.
inline bool syscall_instrumentation_active() {
    static const bool active = detect_syscall_instrumentation();
    return active;
}

/// Reusable in-memory identity provider for permission/security tests.
class MockIdentity : public Voix::IIdentity {
public:
    struct MockUser {
        std::string name;
        uid_t uid;
        gid_t gid;
        std::vector<gid_t> groups;
    };
    std::vector<MockUser> users;
    std::string current_user;
    uid_t current_uid = 0;
    std::vector<gid_t> current_groups;

    std::optional<Voix::UserIdentity> get_user_by_name(const std::string& username) const override {
        for (const auto& u : users) {
            if (u.name == username)
                return Voix::UserIdentity{u.name, u.uid, u.gid, u.groups, "/home/" + u.name, "/bin/bash"};
        }
        return std::nullopt;
    }
    std::optional<Voix::UserIdentity> get_user_by_uid(uid_t uid) const override {
        for (const auto& u : users) {
            if (u.uid == uid)
                return Voix::UserIdentity{u.name, u.uid, u.gid, u.groups, "/home/" + u.name, "/bin/bash"};
        }
        return std::nullopt;
    }
    std::string get_current_username() const override { return current_user; }
    uid_t get_current_uid() const override { return current_uid; }
    std::vector<gid_t> get_current_groups() const override { return current_groups; }
};

/// Removes a file/directory tree on scope exit.
class ScopedTempFile {
public:
    explicit ScopedTempFile(std::filesystem::path path, bool is_dir = false)
        : path_(std::move(path)), is_dir_(is_dir) {}
    ~ScopedTempFile() {
        std::error_code ec;
        if (is_dir_) {
            std::filesystem::remove_all(path_, ec);
        } else {
            std::filesystem::remove(path_, ec);
        }
    }
    std::filesystem::path path() const { return path_; }
private:
    std::filesystem::path path_;
    bool is_dir_;
};

// Per-module registration functions.
void register_permission_tests(TestRunner& runner);
void register_config_tests(TestRunner& runner);
void register_security_tests(TestRunner& runner);
void register_command_tests(TestRunner& runner);
void register_file_utils_tests(TestRunner& runner);
void register_logger_tests(TestRunner& runner);
void register_system_utils_tests(TestRunner& runner);
void register_negative_security_tests(TestRunner& runner);
void register_integration_tests(TestRunner& runner);
