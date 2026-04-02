/**
 * @file main.cpp
 * @brief Enhanced Voix main entry point with OpenDoas integration
 * @copyright Copyright (C) 2026 Veridian Zenith
 * @author Dae Euhwa <daedaevibin@ik.me>
 *
 * All code in this repository is licensed under OSL v3.
 */

#include <print>
#include <string>
#include <vector>
#include <cstdlib>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <cstring>
#include <memory>
#include <sys/capability.h>
#include <getopt.h>
#include "voix.h"
#include "config.h"
#include "security.h"

#if BUILD_TESTING
#include "tests/test_main.h"
#endif

void printUsage() {
    std::print("Usage: voix [options] <incantation> [args...]\n\n"
               "Options:\n"
               "  -h             Show this help message\n"
               "  -v             Show the version of this artifact\n"
               "  -u USER        Execute as target mask (default: root)\n"
               "  -c FILE        Use FILE as the configuration sanctuary\n"
               "  -n             Non-interactive mode (fail if proof is required)\n"
               "  -s             Execute user's shell (ascend to shell)\n\n"
               "Examples:\n"
               "  voix ls /root\n"
               "  voix -u admin systemctl restart nginx\n"
               "  voix -s          # Start interactive shell ascension\n");
}

void printVersion() {
    std::print("Voix version 2.8.0 - The Keeper of Realms\n"
               "Copyright © 2026 Veridian Zenith\n"
               "Architected by Dae Euhwa <daedaevibin@ik.me>\n"
               "Licensed under the Open Software License v3\n");
}

int main(int argc, char* argv[]) noexcept {
    try {
        if (argc < 2) {
            printUsage();
            return 1;
        }

        // Parse command line arguments (enhanced with OpenDoas options)
        std::string target_user = "root";
        std::string config_path = "/etc/voix.conf";
        std::vector<std::string> command_args;
        bool nflag = false;
        bool sflag = false;
        Voix::CommandOptions options;

        if (argc > 1 && strcmp(argv[1], "--run-tests") == 0) {
#if BUILD_TESTING
            return run_tests(argc, argv);
#else
            std::println(stderr, "Tests are not enabled in this build.");
            return 1;
#endif
        }

        int ch;
        static struct option long_options[] = {
            {"login", no_argument, nullptr, 'i'},
            {"preserve-env", no_argument, nullptr, 'E'},
            {"list", no_argument, nullptr, 'l'},
            {"help", no_argument, nullptr, 'h'},
            {"version", no_argument, nullptr, 'v'},
            {nullptr, 0, nullptr, 0}
        };

        while ((ch = getopt_long(argc, argv, "+C:Eilnsu:vh", long_options, nullptr)) != -1) {
            switch (ch) {
                case 'C':
                    config_path = optarg;
                    break;
                case 'E':
                    options.preserve_env = true;
                    break;
                case 'i':
                    options.login_shell = true;
                    break;
                case 'l':
                    options.list_commands = true;
                    break;
                case 'u':
                    target_user = optarg;
                    break;
                case 'n':
                    nflag = true;
                    break;
                case 's':
                    sflag = true;
                    break;
                case 'v':
                    printVersion();
                    return 0;
                case 'h':
                    printUsage();
                    return 0;
                default:
                    std::println(stderr, "Error: Unknown option: {}", static_cast<char>(ch));
                    printUsage();
                    return 1;
            }
        }
        argc -= optind;
        argv += optind;

        // Handle shell mode
        if (sflag) {
            char* shell_env = getenv("SHELL");
            char* shell = nullptr;
            if (!shell_env || !*shell_env) {
                struct passwd pwd;
                struct passwd* pw = nullptr;
                long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
                if (bufsize == -1) bufsize = 16384;
                std::vector<char> buffer(static_cast<size_t>(bufsize));

                if (getpwuid_r(getuid(), &pwd, buffer.data(), buffer.size(), &pw) == 0 && pw) {
                    shell = strdup(pw->pw_shell);
                } else {
                    shell = strdup("/bin/sh");
                }
            } else {
                shell = strdup(shell_env);
            }
            command_args.push_back(shell);
            free(shell);
        } else if (argc < 1 && !options.list_commands) {
            std::println(stderr, "Error: No command specified");
            printUsage();
            return 1;
        } else {
            for (int i = 0; i < argc; ++i) {
                command_args.push_back(argv[i]);
            }
        }

        Voix::Security security;

        try {
            security.raiseCapabilities();
            // Initialize Voix with enhanced configuration
            Voix::Voix voix(config_path, nflag, options.list_commands);

            std::string command = "";
            std::vector<std::string> args;
            if (!command_args.empty()) {
              command = command_args[0];
              args = std::vector<std::string>(command_args.begin() + 1, command_args.end());
            }

            // Execute command with enhanced security
            int result = 0;
            if (options.list_commands) {
                // TODO: Implement list_commands logic here
                std::println("List commands not yet implemented.");
            } else {
                result = voix.execute(command, args, options, target_user);

                // Log successful execution
                syslog(LOG_AUTHPRIV | LOG_INFO, "Command executed: %s as %s",
                      command.c_str(), target_user.c_str());
            }

            security.dropCapabilities();
            return result;
        } catch (const std::exception& e) {
            std::println(stderr, "Error: {}", e.what());
            syslog(LOG_AUTHPRIV | LOG_ERR, "Voix error: %s", e.what());
            security.dropCapabilities();
            return 1;
        }
    } catch (const std::exception& e) {
        std::println(stderr, "Error: {}", e.what());
        syslog(LOG_AUTHPRIV | LOG_ERR, "Voix error: %s", e.what());
        return 1;
    } catch (...) {
        std::println(stderr, "Error: Unknown exception occurred");
        syslog(LOG_AUTHPRIV | LOG_ERR, "Voix error: Unknown exception");
        return 1;
    }
}
