# Voix - Simple Privilege Escalation Tool

**© 2025 Veridian Zenith** - Licensed under OSL v3

## Overview

Voix is a lightweight, simple replacement for sudo and doas, designed for modern Linux systems with a focus on security, performance, and ease of use. Built with C++20 and optimized with LLVM/clang thin LTO and TCMalloc.

## Features

- **Simple Syntax**: Easy-to-use command-line interface
- **Security-First**: Comprehensive validation and security checks
- **Performance Optimized**: Built with LLVM/clang thin LTO and TCMalloc
- **Configuration-Based**: Flexible permission system via config files
- **Modern C++**: Built with C++20 standards
- **Logging**: Comprehensive audit logging
- **User-Specific Permissions**: Granular command access control

## Installation

### Requirements

- Fedora 43+ (or compatible distributions)
- LLVM/clang 21.1.6+
- CMake 3.18+
- TCMalloc (gperftools)

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/Veridian-Zenith/Voix.git
cd Voix

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build the project
make

# Install (optional)
sudo make install
```

## Usage

### Basic Syntax

```bash
voix [options] <command> [args...]
```

### Options

- `-h, --help`: Show help message
- `-v, --version`: Show version information
- `-u, --user`: Specify target user (default: root)
- `-c, --config`: Specify config file path

### Examples

```bash
# Execute command as root
voix ls /root

# Execute command as specific user
voix -u admin systemctl restart nginx

# Execute package manager commands
voix apt update
voix dnf install vim

# Execute with custom config
voix -c /path/to/custom.conf systemctl status
```

## Configuration

Voix uses a simple configuration file format located by default at `/etc/voix.conf`.

### Configuration Format

```ini
# Global settings
key = value

# User permissions
username:command1,command2,command3

# Allowed users list
allowed_users = user1,user2,user3
```

### Example Configuration

```ini
# Allow root to execute any command
root:*

# Allow admin specific system commands
admin:systemctl,apt,yum,dnf,ls,cat,grep

# Allow deploy user git and web server commands
deploy:git,systemctl,nginx,apache2

# Specify allowed users
allowed_users = root,admin,deploy

# Global settings
log_level = INFO
log_file = /var/log/voix.log
```

## Security Features

- **Command Validation**: Prevents execution of dangerous commands
- **Path Safety Checks**: Blocks path traversal attempts
- **Shell Metacharacter Filtering**: Prevents command injection
- **User Authentication**: Validates user permissions
- **Audit Logging**: Comprehensive logging of all actions
- **Security Hardening**: Built with security compiler flags

## Architecture

### Core Components

- **Voix Class**: Main entry point and orchestration
- **Config Class**: Configuration file management
- **Security Class**: Validation and security checks
- **Utils Class**: System utilities and command execution

### Technology Stack

- **Language**: C++20
- **Compiler**: LLVM/clang with thin LTO
- **Memory Allocator**: TCMalloc (gperftools)
- **Build System**: CMake
- **Security**: Comprehensive validation and logging

## Performance

Voix is optimized for performance:
- **Thin LTO**: Optimized binary size and execution speed
- **TCMalloc**: High-performance memory allocation
- **Minimal Dependencies**: Reduced attack surface and faster startup
- **Efficient Code**: Modern C++ features for optimal performance

## Security Considerations

### Blocked Commands

The following commands are blocked for security:
- `su`, `sudo`, `doas`, `pkexec`
- `bash`, `sh`, `zsh`, `fish`
- `dd`, `mkfs`, `fdisk`, `parted`
- `rm`, `rmdir`, `chmod`, `chown`
- `kill`, `killall`, `pkill`
- `systemctl`, `service`
- `chroot`, `unshare`, `nsenter`, `capsh`

### Security Best Practices

1. **Configuration File Permissions**: Ensure config files are readable only by root
2. **Audit Logs**: Regularly review `/var/log/voix.log`
3. **User Permissions**: Grant minimum necessary permissions
4. **Command Validation**: Review allowed commands regularly
5. **System Updates**: Keep the system and Voix updated

## Troubleshooting

### Common Issues

**Permission Denied**
- Check if user is in `allowed_users` list
- Verify config file syntax and permissions

**Command Not Allowed**
- User may not have permission for specific command
- Check user-specific command configuration

**Configuration Not Loading**
- Verify config file path and syntax
- Check file permissions

### Debug Mode

Enable debug logging by setting `log_level = DEBUG` in configuration.

## Racket Integration

Voix supports Racket scripting for advanced configuration and automation:

```racket
#lang racket

(require vozr)  ; Voix Racket bindings

; Execute commands through Voix
(voix-execute "ls" '("/root"))

; Check user permissions
(voix-check-permission "admin" "systemctl")

; Load custom configuration
(voix-load-config "/path/to/custom.conf")
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the Open Software License 3.0 (OSL-3.0). See LICENSE file for details.

## Copyright

© 2025 Veridian Zenith. All rights reserved.

---

**Voix** - Simple, Secure, Fast privilege escalation for modern Linux systems.
