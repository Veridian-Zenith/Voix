# Voix - Arch Linux Package Information

This document provides information for installing Voix on Arch Linux via AUR.

## Overview

Voix is a modern privilege escalation tool designed to replace sudo, doas, and sudo-rs, with PAM authentication support built-in.

## Installation from AUR

```bash
# Clone the AUR package
git clone https://aur.archlinux.org/voix.git
cd voix

# Build and install
makepkg -si
```

## Key Features

- **PAM Integration**: Uses Pluggable Authentication Modules (PAM) for flexible authentication
- **Lua Configuration**: Modern Lua-based access control rules
- **Setuid Binary**: Automatically installed with proper permissions
- **Drop-in Sudo Replacement**: Creates `/usr/bin/sudo` symlink to voix

## Configuration Files

After installation, configure the following files:

### 1. Main Configuration (`/etc/voix.conf`)
Simple rule-based configuration file. Example:
```
root allow nopass
group:wheel allow
group:sudo allow
```

### 2. Lua Configuration (`/etc/voix/voix.lua`)
More complex access rules using Lua. Allows:
- Per-user rules
- Per-group rules
- Nopass rules
- Command restrictions

### 3. PAM Configuration (`/etc/pam.d/voix`)
Configured for system authentication. Default uses:
- `pam_unix.so` for Unix password authentication
- `pam_lastlog.so` for session tracking

Modify if you need:
- LDAP authentication: Change to `pam_ldap.so`
- Kerberos: Change to `pam_krb5.so`
- Key-based auth: Add `pam_open_ssh_key.so`

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

## Important Security Notes

1. **Only users in wheel or sudo groups can escalate** by default
2. **Root can execute anything** without a password by default
3. **Configuration files are sensitive** - ensure proper permissions
4. **PAM must be configured correctly** for authentication to work

## Troubleshooting

### "Permission denied" errors
- Check setuid bit: `ls -l /usr/bin/voix` should show 's'
- Fix with: `sudo chmod 4755 /usr/bin/voix`

### "PAM authentication failed"
- Check PAM config: `cat /etc/pam.d/voix`
- Ensure pam_unix.so is available: `ls /usr/lib/security/pam_unix.so`

### Lua configuration not working
- Check Lua syntax: `lua -c /etc/voix/voix.lua`
- Verify file permissions: `ls -l /etc/voix/voix.lua`

## Dependencies

- **Runtime**: `pam` (Pluggable Authentication Modules)
- **Build**: `cmake >= 3.18`, `gcc`, `make`, `pkgconf`, `lua`

All are installed automatically with `makepkg -si`.

## Updating to New Versions

When updating, your configuration files are preserved:
- `/etc/voix.conf` (backed up if changed)
- `/etc/voix/voix.lua` (backed up if changed)
- `/etc/pam.d/voix` (backed up if changed)

Check for `.pacnew` files after upgrade:
```bash
sudo find /etc -name "*.pacnew"
```

## Using Voix as Sudo Replacement

Voix is installed with a symlink from `/usr/bin/sudo` to `/usr/bin/voix`, allowing it to work as a drop-in sudo replacement.

Test it:
```bash
sudo whoami  # Uses voix instead of sudo
```

## Lua Configuration Examples

Simple rule allowing all wheel members:
```lua
{
    group = "wheel",
    nopass = false,
    actions = {"*"}
}
```

Allow specific user to run specific command without password:
```lua
{
    user = "admin",
    nopass = true,
    actions = {"systemctl"}
}
```

## Support

For issues and feature requests:
- GitHub: https://github.com/Veridian-Zenith/Voix
- Issues: https://github.com/Veridian-Zenith/Voix/issues

## License

- Main code: AGPLv3
- OpenDoas integration: BSD-style (see OpenDoas LICENSE)
- VCL 1.0 where applicable
