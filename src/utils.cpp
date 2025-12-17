/**
 * @file utils.cpp
 * @brief Utility functions implementation
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include "utils.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <fcntl.h>
#include <cstdlib>

namespace Voix {

Utils::Utils() = default;

Utils::~Utils() = default;

int Utils::executeCommand(const std::string& command,
                         const std::vector<std::string>& args,
                         const std::optional<std::string>& user) const {

    pid_t pid = fork();

    if (pid == -1) {
        // Fork failed
        return -1;
    } else if (pid == 0) {
        // Child process

        // If user is specified, try to switch user
        if (user.has_value()) {
            struct passwd* pw = getpwnam(user->c_str());
            if (pw) {
                (void)setuid(pw->pw_uid);  // Explicitly ignore return value
                (void)setgid(pw->pw_gid);  // Explicitly ignore return value
            }
        }

        // Build argument array for execvp
        std::vector<const char*> argv;
        argv.push_back(command.c_str());

        for (const auto& arg : args) {
            argv.push_back(arg.c_str());
        }
        argv.push_back(nullptr);

        // Execute command
        execvp(command.c_str(), const_cast<char* const*>(argv.data()));

        // If execvp returns, an error occurred
        _exit(127);
    } else {
        // Parent process - wait for child
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        return -1;
    }
}

bool Utils::fileExists(const std::string& path) const {
    return access(path.c_str(), F_OK) == 0;
}

std::optional<std::string> Utils::readFile(const std::string& path) const {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    return buffer.str();
}

bool Utils::writeFile(const std::string& path, const std::string& content) const {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }

    file << content;
    file.close();

    return file.good();
}

std::string Utils::getTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S")
       << "." << std::setfill('0') << std::setw(3) << ms.count();

    return ss.str();
}

void Utils::log(const std::string& level, const std::string& message) const {
    std::string timestamp = getTimestamp();
    std::string log_entry = "[" + timestamp + "] [" + level + "] " + message;

    // Try to write to syslog first, then to file
    #ifdef __linux__
    // Note: In a real implementation, you'd use syslog() here
    #endif

    // Fallback to file logging
    std::ofstream log_file("/var/log/voix.log", std::ios::app);
    if (log_file.is_open()) {
        log_file << log_entry << std::endl;
        log_file.close();
    }
}

std::string Utils::buildCommandString(const std::string& command,
                                     const std::vector<std::string>& args,
                                     const std::optional<std::string>& user) const {
    std::stringstream ss;

    if (user.has_value()) {
        ss << "su - " << user.value() << " -c ";
    }

    ss << command;

    for (const auto& arg : args) {
        ss << " " << arg;
    }

    return ss.str();
}

} // namespace Utils
