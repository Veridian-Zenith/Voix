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
#include <cstring>
#include <memory>
#ifdef VOIX_WITH_CAP
#include <sys/capability.h>
#endif
#include <getopt.h>
#include "voix.hpp"
#include "config.hpp"
#include "exit_code.hpp"
#include "logger.hpp"
#include "security.hpp"
#include "system_utils.hpp"
#include "policy_analyzer.hpp"

#if BUILD_TESTING
#include "tests/test_main.hpp"
#endif

#ifndef VOIX_VERSION
#define VOIX_VERSION "4.14.0"
#endif

/**
 * @brief Prints the usage information for the voix command.
 */
void printUsage() {
    std::print("Usage: voix [options] <incantation> [args...]\n\n"
               "Options:\n"
               "  -h, --help               Show this help message\n"
               "  -v, --version            Show the version of this artifact\n"
               "  -u USER                  Execute as target user (default: root)\n"
               "  -C, --config FILE        Use FILE as the configuration sanctuary\n"
               "  -c, --check-config       Validate the configuration file\n"
               "  -n                       Non-interactive mode (fail if proof is required)\n"
               "  -s                       Execute user's shell (ascend to shell)\n"
               "  -l, --list               List permitted commands for the current user\n"
               "  -E, --preserve-env       Preserve the environment (requires keepenv policy)\n"
               "  -H, --home               Set HOME to the target user's home directory\n"
               "  -i, --login              Execute in a login shell\n"
               "  -k                       Invalidate persisted authentication timestamps\n\n"
               "Examples:\n"
               "  voix ls /root\n"
               "  voix -u admin systemctl restart nginx\n"
               "  voix -l                  # List permitted commands\n"
               "  voix -s                  # Start interactive shell ascension\n");
}

/**
 * @brief Prints the version information of the voix command.
 */
void printVersion() {
    std::print("Voix version {} - The Keeper of Realms\n"
               "Copyright \u00a9 2026 Veridian Zenith\n"
               "Architected by Dae Euhwa <daedaevibin@ik.me>\n"
               "Licensed under the Open Software License v3\n", VOIX_VERSION);
}

int main(int argc, char* argv[]) noexcept {
    try {
        if (argc < 2) {
            printUsage();
            return Voix::exit_status(Voix::ExitCode::Usage);
        }

        // Parse command line arguments (enhanced with OpenDoas options)
        std::string target_user = "root";
        std::string config_path = "/etc/voix.conf";
        std::vector<std::string> command_args;
        bool nflag = false;
        bool sflag = false;
        bool clear_timestamp = false;
        Voix::CommandOptions options;

        // Note: short-only options 'n', 's', 'u', 'k' in the optstring have
        // no corresponding long_option entries. They remain short-only for
        // compatibility with doas/OpenDoas conventions.

        if (argc > 1 && strcmp(argv[1], "--run-tests") == 0) {
#if BUILD_TESTING
            return VoixTest::run_tests(argc, argv);
#else
            std::println(stderr, "Tests are not enabled in this build.");
            return Voix::exit_status(Voix::ExitCode::Software);
#endif
        }

        int ch;
        static struct option long_options[] = {
            {"login", no_argument, nullptr, 'i'},
            {"preserve-env", no_argument, nullptr, 'E'},
            {"home", no_argument, nullptr, 'H'},
            {"list", no_argument, nullptr, 'l'},
            {"help", no_argument, nullptr, 'h'},
            {"version", no_argument, nullptr, 'v'},
            {"check-config", no_argument, nullptr, 'c'},
            {"config", required_argument, nullptr, 'C'},
            {nullptr, 0, nullptr, 0}
        };

        while ((ch = getopt_long(argc, argv, "+C:EiHlnsu:vhck", long_options, nullptr)) != -1) {
            switch (ch) {
                case 'C':
                    config_path = optarg;
                    break;
                case 'E':
                    options.preserve_env = true;
                    break;
                case 'H':
                    options.set_home = true;
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
                    clear_timestamp = true;
                    break;
                default:
                    // getopt_long already prints an error for unknown options
                    printUsage();
                    return Voix::exit_status(Voix::ExitCode::Usage);
            }
        }
        argc -= optind;
        argv += optind;

        // Interactive modes run the target account's login shell. The
        // caller's $SHELL is caller-controlled and must never influence a
        // privilege transition, so resolve_login_shell() reads the target's
        // passwd entry instead.
        if (sflag || (options.login_shell && argc < 1)) {
            // -s, or -i without a command: open a login shell as the target.
            command_args.push_back(Voix::resolve_login_shell(target_user));
        } else if (argc < 1 && !options.list_commands && !options.check_config &&
                   !clear_timestamp && !options.login_shell) {
            Voix::Logger().report_error(
                Voix::ExitCode::Usage, "no command specified",
                "run 'voix --help' for usage, or 'voix -l' to list permitted "
                "commands");
            return Voix::exit_status(Voix::ExitCode::Usage);
        } else if (argc > 0) {
            for (int i = 0; i < argc; ++i) {
                command_args.push_back(argv[i]);
            }
        }

        if (options.check_config) {
            Voix::Config config;
            if (!config.load(config_path, true)) {
                Voix::Logger().report_error(
                    Voix::ExitCode::Config, config.last_error(),
                    "check that the file exists, is root-owned, and has no "
                    "group/world write permission");
                return Voix::exit_status(Voix::ExitCode::Config);
            }
            if (!config.validate()) {
                Voix::Logger().report_error(
                    Voix::ExitCode::Config, config.last_error(),
                    "fix the reported setting and re-run 'voix --check-config'");
                return Voix::exit_status(Voix::ExitCode::Config);
            }
            std::println("Configuration is valid.");

            Voix::PolicyAnalyzer analyzer(config);
            auto findings = analyzer.analyze();
            if (!findings.empty()) {
                std::println("\nPolicy analysis:");
                for (const auto& f : findings) {
                    const char* severity = (f.severity == Voix::PolicyFinding::Severity::ERROR)
                        ? "error" : "warning";
                    std::println("  [{}] {}", severity, f.message);
                }
            }
            return Voix::exit_status(Voix::ExitCode::Success);
        }

        Voix::Security security;

        try {
#ifdef VOIX_WITH_CAP
            security.raiseCapabilities();
#endif
            // Initialize Voix with enhanced configuration
            Voix::Voix voix(config_path, nflag, clear_timestamp);

            std::string command = "";
            std::vector<std::string> args;
            if (!command_args.empty()) {
              command = command_args[0];
              args = std::vector<std::string>(command_args.begin() + 1, command_args.end());
            }

            // `voix -k` with no command only invalidates timestamps.
            if (clear_timestamp && command.empty()) {
                return 0;
            }

            int result = 0;
            if (options.list_commands) {
                result = voix.list_commands();
            } else {
                result = voix.execute(command, args, options, target_user);
            }

#ifdef VOIX_WITH_CAP
            security.dropCapabilities();
#endif
            return result;
        } catch (const Voix::VoixError& e) {
            Voix::Logger().report_error(e.code(), e.what(), e.hint());
#ifdef VOIX_WITH_CAP
            security.dropCapabilities();
#endif
            return Voix::exit_status(e.code());
        } catch (const std::exception& e) {
            // Keep implementation details (paths, OS errors) in the trusted
            // local audit log; the caller only sees a fixed message.
            Voix::Logger().log(
                Voix::LogLevel::Error,
                std::string("[software] unhandled exception: ") + e.what(),
                /*echo_stderr=*/false);
            Voix::Logger().report_error(
                Voix::ExitCode::Software, "internal error",
                "this is an internal error; re-run with a Debug build and "
                "report it with the log from /var/log/voix.log");
#ifdef VOIX_WITH_CAP
            security.dropCapabilities();
#endif
            return Voix::exit_status(Voix::ExitCode::Software);
        }
    } catch (const Voix::VoixError& e) {
        Voix::Logger().report_error(e.code(), e.what(), e.hint());
        return Voix::exit_status(e.code());
    } catch (const std::exception& e) {
        Voix::Logger().log(
            Voix::LogLevel::Error,
            std::string("[software] unhandled exception: ") + e.what(),
            /*echo_stderr=*/false);
        Voix::Logger().report_error(
            Voix::ExitCode::Software, "internal error",
            "this is an internal error; report it with the log from "
            "/var/log/voix.log");
        return Voix::exit_status(Voix::ExitCode::Software);
    } catch (...) {
        Voix::Logger().report_error(Voix::ExitCode::Software,
                                    "unknown exception occurred",
                                    "this is an internal error");
        return Voix::exit_status(Voix::ExitCode::Software);
    }
}
