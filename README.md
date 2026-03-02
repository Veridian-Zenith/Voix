# Voix - A Secure Privilege Management Tool

## Overview

Voix is a secure privilege management tool designed to provide controlled command execution with elevated privileges. Unlike traditional sudo implementations, Voix focuses on security and simplicity while incorporating modern authentication methods.

**Built from scratch but inspired by OpenDoas**, Voix provides a secure alternative to sudo with PAM authentication support built-in.

**Note**: Voix is currently only available via the Arch User Repository (AUR).

## Features

- **Controlled Privilege Escalation**: Execute commands with elevated privileges only when explicitly configured
- **PAM Authentication**: Secure authentication using Pluggable Authentication Modules
- **Lua Configuration**: Modern Lua-based access control rules
- **Shell Integration**: Properly executes commands within the user's shell environment
- **Security First**: Built-in protection against dangerous commands and shell injection
- **Timestamp Support**: Optional persist authentication (similar to sudo)

## Installation

### Arch Linux AUR Installation

For Arch Linux users, Voix is available in the AUR:

```bash
# Clone the AUR package
git clone https://aur.archlinux.org/voix.git
cd voix

# Build and install
makepkg -si
```

### Dependencies

Automatically installed with `makepkg -si`:

- `pam` - Pluggable Authentication Modules
- `cmake>=3.18` - Build system
- `gcc` - C++ compiler
- `make` - Build tool
- `pkgconf` - Package configuration

## Configuration

Voix is configured via simple configuration file at `/etc/voix.conf`.

### Main Configuration (`/etc/voix.conf`)

Simple rule-based configuration file. Example:

```
root allow nopass
group:wheel allow
group:sudo allow
```

### 3. PAM Configuration (`/etc/pam.d/voix`)

Configured for system authentication. Default uses:

- `pam_unix.so` for Unix password authentication
- `pam_lastlog.so` for session tracking

Modify if you need:

- LDAP authentication: Change to `pam_ldap.so`
- Kerberos: Change to `pam_krb5.so`
- Key-based auth: Add `pam_open_ssh_key.so`

Default PAM configuration:

```
#%PAM-1.0
auth       include    system-auth
account    include    system-auth
session    include    system-auth
```

## Usage

To run a command with elevated privileges:

```bash
voix <command> [args...]
```

### Common Examples

```bash
# Run a command as root
voix whoami

# Run a command as a specific user
voix -u username whoami

# Start a shell as root
voix -S

# Check configuration without executing
voix -C /etc/voix.conf
```

### Command Line Options

- `-h, --help`: Show help message and exit
- `-v, --version`: Show version information and exit
- `-u USER, --user USER`: Execute command as specified user (default: root)
- `-g GROUP, --group GROUP`: Execute command as specified group
- `-S, --shell`: Start a shell as the target user
- `-C CONFIG`: Check configuration file

## Security Notes

- **Setuid Binary**: Voix must be owned by root with the setuid bit set for proper operation
- **PAM Required**: Authentication depends on proper PAM configuration
- **Command Validation**: Built-in protection against dangerous commands
- **Shell Injection Protection**: Validates commands and arguments for safety
- **Logging**: All commands are logged to `/var/log/voix.log`

## Post-Installation Setup

### Verify Installation

```bash
# Test basic functionality
voix whoami

# Test as different user
voix -u root whoami

# Check man page
man voix
```

### Verify Permissions

```bash
# Check binary has setuid bit
ls -l /usr/bin/voix

# Should show: -rwsr-xr-x (or similar with 's' bit)
```

### Verify PAM Configuration

```bash
# View current PAM config
cat /etc/pam.d/voix

# Test PAM is working (may prompt for password)
voix id
```

## Troubleshooting

### "Permission denied" errors

- Check setuid bit: `ls -l /usr/bin/voix` should show 's'
- Fix with: `sudo chmod 4755 /usr/bin/voix`

### "PAM authentication failed"

- Check PAM config: `cat /etc/pam.d/voix`
- Ensure pam_unix.so is available: `ls /usr/lib/security/pam_unix.so`

### "Command not permitted" errors

- Check your user is in allowed groups (wheel, sudo)
- Verify configuration syntax
- Check logs: `tail -f /var/log/voix.log`

## Dependencies

- **Runtime**: `pam` (Pluggable Authentication Modules)
- **Build**: `cmake >= 3.18`, `gcc`, `make`, `pkgconf`

## License

Voix is licensed under the GNU Affero General Public License v3.0.

This software includes components derived from OpenDoas:
- Copyright (c) 2015 Ted Unangst
- Copyright (c) 2015 Nathan Holstein
- Copyright (c) 2016 Duncan Overbruck

See the LICENSE file for full licensing details.

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and feature requests:

- GitHub: <https://github.com/Veridian-Zenith/Voix>
- Issues: <https://github.com/Veridian-Zenith/Voix/issues>

## Related Projects

- [OpenDoas](https://github.com/dimkr/doas): The original doas implementation
- [sudo](https://www.sudo.ws/): Traditional privilege escalation tool
- [PAM](https://www.linux-pam.org/): Pluggable Authentication Modules

## Security Considerations

- Always keep Voix updated to the latest version
- Regularly review and audit configuration files
- Monitor authentication logs for suspicious activity
- Use strong, unique passwords for all users
- Consider using multi-factor authentication where possible

## Performance

Voix is designed to be lightweight and fast:

- Minimal memory footprint
- Fast authentication through PAM
- Efficient command validation
- No unnecessary background processes

## Development

### Building for Development

```bash
# Clone with submodules
git clone --recursive https://github.com/Veridian-Zenith/Voix.git
cd Voix

# Build with debug symbols
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Run tests (if available)
cd build && ctest
```

### Code Style

- Follow existing code style in the project
- Use meaningful variable names
- Add appropriate comments for complex logic
- Ensure all changes pass existing tests

## Changelog

### Version 2.0.0
- Complete rewrite with modern C++
- Added Lua configuration support
- Enhanced security features
- Improved PAM integration
- Better error handling and logging

### Version 1.x.x
- Initial implementation based on OpenDoas
- Basic configuration support
- Simple authentication mechanism

## Acknowledgments

Voix builds upon the excellent work of the OpenDoas project and the OpenBSD community. Special thanks to:

- Ted Unangst for creating doas
- The OpenBSD project for their security-focused approach
- All contributors to the original doas implementation
