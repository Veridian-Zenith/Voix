/---
name: Bug report
about: Report a bug to help us improve
title: '[BUG] '
labels: ['bug', 'needs-triage']
assignees: ''
---

## Bug Description

A clear and concise description of what the bug is.

## Steps to Reproduce

Steps to reproduce the behavior:

1. Go to '...'
2. Run command '...'
3. See error

**Expected behavior:**
A clear and concise description of what you expected to happen.

**Actual behavior:**
What actually happened instead.

## Environment Information

- **OS:** (e.g., Arch Linux, Ubuntu 22.04, Fedora 38)
- **Kernel:** (output of `uname -r`)
- **Voix Version:** (output of `voix --version` or commit hash)
- **Build Method:** (AUR, from source, etc.)
- **PAM Version:** (output of `pam --version` if available)

## Configuration Details

**Main Configuration (`/etc/voix.conf`):**
```bash
# Please paste your voix.conf content here (remove sensitive info)
```

**PAM Configuration (`/etc/pam.d/voix`):**
```bash
# Please paste your PAM configuration here
```

## Error Logs

Please provide relevant logs from:
- `/var/log/voix.log`
- System logs (`journalctl -u voix` if applicable)
- Terminal output with error messages

```bash
# Paste relevant log entries here
```

## Additional Context

Add any other context about the problem here:

- Screenshots or terminal output
- Recent system changes
- Other authentication tools installed
- Any custom configurations

## Reproduction Frequency

- [ ] Always reproducible
- [ ] Intermittent
- [ ] Only under specific conditions
- [ ] Only with certain commands

## Security Considerations

- [ ] This bug may have security implications
- [ ] Contains sensitive configuration information
- [ ] Affects authentication/authorization

**If this is a security-sensitive bug, please report it through our security policy instead:**
https://github.com/Veridian-Zenith/Voix/security/policy

## Attempted Workarounds

Describe any workarounds you've tried:

1.
2.
3.

## Related Issues

- [ ] This is a regression (worked in previous version)
- [ ] Related to issue # (link if applicable)
- [ ] Duplicate of existing issue # (link if applicable)
