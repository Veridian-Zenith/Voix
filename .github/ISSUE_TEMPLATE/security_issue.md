---
name: Security Issue
about: Report a security vulnerability
title: '[SECURITY] '
labels: ['security', 'critical']
assignees: ''
---

## Security Issue Description

**⚠️ IMPORTANT: Do not disclose security vulnerabilities in public issues. ⚠️**

This template is for reporting security vulnerabilities. If you believe you've found a security issue, please use this form to report it confidentially.

## Vulnerability Type

- [ ] Authentication bypass
- [ ] Privilege escalation
- [ ] Command injection
- [ ] Shell injection
- [ ] Buffer overflow
- [ ] Race condition
- [ ] Information disclosure
- [ ] Denial of service
- [ ] Other: _______________

## Severity Assessment

- [ ] Critical (immediate fix required)
- [ ] High (fix needed within 48 hours)
- [ ] Medium (fix needed within 1 week)
- [ ] Low (fix can be scheduled)

## Description

A clear and concise description of the security vulnerability:

## Steps to Reproduce

**⚠️ WARNING: Only provide reproduction steps if you can do so safely and without causing harm. ⚠️**

If applicable, describe how to reproduce the vulnerability:

1.
2.
3.

## Impact Assessment

Describe the potential impact of this vulnerability:

- **Confidentiality impact:**
- **Integrity impact:**
- **Availability impact:**
- **Affected users:**

## Proof of Concept

If you have a proof of concept, please describe it:

**⚠️ DO NOT include actual exploit code or sensitive details in this public repository. ⚠️**

## Environment Information

- **OS:** (e.g., Arch Linux, CachyOS, etc.)
- **Voix Version:** (output of `voix --version` or commit hash)
- **Build Method:** (AUR, from source, etc.)
- **PAM Version:** (if applicable)

## Affected Components

- [ ] Authentication module
- [ ] Configuration parser
- [ ] Command execution
- [ ] PAM integration
- [ ] Logging system
- [ ] Setuid binary
- [ ] Other: _______________

## Potential Exploitation

Describe how this vulnerability could potentially be exploited:

## Mitigation Attempts

Have you attempted any mitigations?

- [ ] Yes (describe):
- [ ] No

## Additional Context

Add any other context about the security issue here:

- Links to related research or CVEs
- Similar vulnerabilities in other projects
- Timeline of discovery
- Any communication with maintainers

## Contact Information

If you'd like to be contacted regarding this issue:

- **Email:** daedaevibin@naver.com (for sensitive details)
- **PGP Key:** (optional, for encrypted communication)

## Responsible Disclosure

By submitting this issue, you agree to:

- [ ] Allow the maintainers to investigate and fix the issue
- [ ] Not publicly disclose the vulnerability until a fix is released
- [ ] Cooperate with maintainers during the investigation
- [ ] Follow responsible disclosure practices

## Alternative Reporting

If you prefer to report this security issue through alternative channels:

- **Security Policy:** <https://github.com/Veridian-Zenith/Voix/blob/main/.github/SECURITY.md>
- **Email:** daedaevibin@naver.com
- **Encrypted communication:** Available upon request

**Note:** This issue will be treated as a security vulnerability and handled according to our security policy.
