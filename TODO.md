# Voix TODO List

This file tracks planned features, enhancements, and bug fixes for the Voix project.

## High Priority

- **Set Up Continuous Integration (CI):** Create a CI pipeline (e.g., using GitHub Actions) to automatically build and test the project on every push and pull request. This will help catch regressions and ensure that the code always remains in a buildable state.

## Medium Priority

- **Enhance Configuration Options:**
  - Add support for command aliases in `voix.conf`.
  - Implement a mechanism for preserving specific environment variables.
- **Address `clang-tidy` Warnings:** Systematically review and fix the remaining `bugprone` and `performance` warnings identified by `clang-tidy`.
- **Improve Shell Integration:** The `-s` flag for starting a shell is currently basic. It could be enhanced to provide a more seamless and feature-rich experience, similar to `sudo -s`.

## Low Priority

- **Advanced Logging:**
  - Implement different log levels (e.g., debug, info, warn, error).
  - Add support for configuring the log output destination (e.g., syslog, file, stderr).
- **Expand Platform Support:** Test and document the build process for other Linux distributions and potentially other Unix-like operating systems.
