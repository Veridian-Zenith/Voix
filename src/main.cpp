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
#include <syslog.h>
#include <cstring>
#include <memory>
#include <sys/capability.h>
#include <getopt.h>
#include "voix.hpp"
#include "config.hpp"
#include "security.hpp"
#include "system_utils.hpp"

#if BUILD_TESTING
#include "tests/test_main.hpp"
#endif

/**
 * @brief Prints the usage information for the voix command.
 */
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

/**
 * @brief Prints the version information of the voix command.
 */
void printVersion() {
    std::print("Voix version 4.3.3 - The Keeper of Realms\n"
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
            {"check-config", no_argument, nullptr, 'c'},
            {nullptr, 0, nullptr, 0}
        };

        while ((ch = getopt_long(argc, argv, "+C:Eilnsu:vhck", long_options, nullptr)) != -1) {
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
                case 'c':
                    options.check_config = true;
                    break;
                case 'k':
                    // sudo -k: invalidate timestamp. No-op for voix.
                    break;
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
            std::string shell;
            if (!shell_env || !*shell_env) {
                auto pw_entry = Voix::lookupPasswdByUid(getuid());
                shell = pw_entry ? pw_entry->shell : "/bin/sh";
            } else {
                shell = shell_env;
            }
            command_args.push_back(shell);
        } else if (argc < 1 && !options.list_commands) {
            std::println(stderr, "Error: No command specified");
            printUsage();
            return 1;
        } else if (argc > 0) {
            for (int i = 0; i < argc; ++i) {
                command_args.push_back(argv[i]);
            }
        }
        
        if (options.check_config) {
            Voix::Config config;
            if (!config.load(config_path, true) || !config.validate()) {
                std::println(stderr, "Error: Invalid configuration schema or permissions.");
                return 1;
            }
            std::println("Configuration is valid.");
            return 0;
        }

        Voix::Security security;

        try {
#ifdef VOIX_WITH_CAP
            security.raiseCapabilities();
#endif
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

#ifdef VOIX_WITH_CAP
            security.dropCapabilities();
#endif
            return result;
        } catch (const std::exception& e) {
            std::println(stderr, "Error: {}", e.what());
            syslog(LOG_AUTHPRIV | LOG_ERR, "Voix error: %s", e.what());
#ifdef VOIX_WITH_CAP
            security.dropCapabilities();
#endif
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
