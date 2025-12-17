/**
 * @file main.cpp
 * @brief Main entry point for Voix
 * @copyright © 2025 Veridian Zenith All code in this repository is licensed under OSL v3.
 */

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include "voix.h"
#include "config.h"
#include "security.h"
#include "utils.h"

void printUsage() {
    std::cout << "Usage: voix [options] <command> [args...]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help     Show this help message\n";
    std::cout << "  -v, --version  Show version information\n";
    std::cout << "  -u, --user     Specify target user (default: root)\n";
    std::cout << "  -c, --config   Specify config file path\n\n";
    std::cout << "Examples:\n";
    std::cout << "  voix ls /root\n";
    std::cout << "  voix -u admin systemctl restart nginx\n";
    std::cout << "  voix apt update\n";
}

void printVersion() {
    std::cout << "Voix version 1.0.0\n";
    std::cout << "Copyright © 2025 Veridian Zenith\n";
    std::cout << "Licensed under OSL v3\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage();
        return 1;
    }

    // Parse command line arguments
    std::string target_user = "root";
    std::string config_path = "/etc/voix.conf";
    std::vector<std::string> command_args;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            printUsage();
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            printVersion();
            return 0;
        } else if (arg == "-u" || arg == "--user") {
            if (i + 1 < argc) {
                target_user = argv[++i];
            } else {
                std::cerr << "Error: --user requires an argument\n";
                return 1;
            }
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                config_path = argv[++i];
            } else {
                std::cerr << "Error: --config requires an argument\n";
                return 1;
            }
        } else {
            // This is the command to execute
            command_args.push_back(arg);
            // Add remaining arguments
            for (int j = i + 1; j < argc; ++j) {
                command_args.push_back(argv[j]);
            }
            break;
        }
    }

    if (command_args.empty()) {
        std::cerr << "Error: No command specified\n";
        printUsage();
        return 1;
    }

    // Initialize Voix with config path
    Voix::Voix voix(config_path);

    // Check if user is allowed
    if (!voix.isAllowed()) {
        std::cerr << "Error: Current user is not allowed to use Voix\n";
        return 1;
    }

    // Validate command
    std::string command = command_args[0];
    std::vector<std::string> args(command_args.begin() + 1, command_args.end());

    if (!voix.validateCommand(command)) {
        std::cerr << "Error: Command '" << command << "' is not allowed\n";
        return 1;
    }

    // Execute command
    int result = voix.execute(command, args, target_user);

    return result;
}
