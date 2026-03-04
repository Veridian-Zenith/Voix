/**
 * @file main.cpp
 * @brief Enhanced Voix main entry point with OpenDoas integration
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>
#include <cstring>
#include <memory>
#include "voix.h"
#include "config.h"
#include "security.h"

void printUsage() {
    std::cout << "Usage: voix [options] <command> [args...]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h             Show this help message\n";
    std::cout << "  -v             Show version information\n";
    std::cout << "  -u USER        Execute as USER (default: root)\n";
    std::cout << "  -c FILE        Use FILE as config (default: /etc/voix.conf)\n";
    std::cout << "  -n             Non-interactive mode\n";
    std::cout << "  -s             Execute user's shell\n\n";
    std::cout << "Examples:\n";
    std::cout << "  voix ls /root\n";
    std::cout << "  voix -u admin systemctl restart nginx\n";
    std::cout << "  voix pacman -Syu\n";
    std::cout << "  voix -s          # Start interactive shell (WIP)\n";
}

void printVersion() {
    std::cout << "Voix version 2.2.0\n";
    std::cout << "Copyright © 2026 Veridian Zenith\n";
    std::cout << "Licensed under OSL v3\n";
}

int main(int argc, char* argv[]) {
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
    bool Lflag = false;

    int ch;
    while ((ch = getopt(argc, argv, "+C:Lnsu:vh")) != -1) {
        switch (ch) {
            case 'C':
                config_path = optarg;
                break;
            case 'L':
                Lflag = true;
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
                std::cerr << "Error: Unknown option: " << static_cast<char>(ch) << '\n';
                printUsage();
                return 1;
        }
    }
    argc -= optind;
    argv += optind;

    // Handle shell mode
    if (sflag) {
        char* shell = getenv("SHELL");
        if (!shell || !*shell) {
            struct passwd* pw = getpwuid(getuid());
            if (pw) {
                shell = strdup(pw->pw_shell);
            } else {
                shell = strdup("/bin/sh");
            }
        }
        command_args.push_back(shell);
        free(shell);
    } else if (argc < 1) {
        std::cerr << "Error: No command specified\n";
        printUsage();
        return 1;
    } else {
        for (int i = 0; i < argc; ++i) {
            command_args.push_back(argv[i]);
        }
    }

    // Check if running as root (setuid requirement)
    // For development/testing, allow running as non-root with warning
    if (geteuid() != 0) {
        std::cerr << "Warning: Not running as root. Privilege escalation may not work.\n";
        std::cerr << "For proper operation, voix should be installed setuid root.\n";
        // Continue execution for testing purposes
    }

    try {
        // Initialize Voix with enhanced configuration
        Voix::Voix voix(config_path, nflag, Lflag);

        std::string command = command_args[0];
        std::vector<std::string> args(command_args.begin() + 1, command_args.end());

        // Execute command with enhanced security
        int result = voix.execute(command, args, target_user);

        // Log successful execution
        syslog(LOG_AUTHPRIV | LOG_INFO, "Command executed: %s as %s",
              command.c_str(), target_user.c_str());

        return result;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        syslog(LOG_AUTHPRIV | LOG_ERR, "Voix error: %s", e.what());
        return 1;
    }
}
