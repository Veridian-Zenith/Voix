# Security Policy

## Supported Versions

We take security seriously in the Voix project. Security updates are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

### How to Report

If you discover a security vulnerability in Voix, please report it responsibly by:

1. **Email**: Send details to daedaevibin@naver.com
2. **Include in your report**:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested fixes or mitigations

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Investigation**: We will investigate and respond with our findings within 5 business days
- **Resolution**: We will work to fix critical vulnerabilities within 30 days
- **Disclosure**: We will coordinate with you on responsible disclosure timing

### Responsible Disclosure

We ask that you:

- Give us reasonable time to investigate and fix the issue before public disclosure
- Do not exploit the vulnerability beyond what is necessary to understand its scope
- Keep details of the vulnerability confidential until we have had time to address it

### What We Don't Consider Security Issues

The following are generally not considered security vulnerabilities:

- Denial of service attacks through resource exhaustion
- Information disclosure through log files
- Clickjacking of the command-line interface
- Social engineering attacks

## Security Best Practices

### For Users

- Keep Voix updated to the latest version
- Use strong, unique passwords for all accounts
- Regularly review and audit your voix.conf configuration
- Monitor `/var/log/voix.log` for suspicious activity
- Use PAM modules appropriate for your security requirements

### For Developers

- Always validate and sanitize user input
- Use secure coding practices
- Follow the principle of least privilege
- Test for common security vulnerabilities
- Review security implications of new features

## Security Configuration

### Recommended PAM Configuration

For enhanced security, consider using:

```bash
# /etc/pam.d/voix
auth       required   pam_unix.so try_first_pass
auth       optional   pam_faildelay.so delay=3000000
account    required   pam_unix.so
session    required   pam_env.so
session    required   pam_unix.so
```

### Secure Configuration Examples

```bash
# /etc/voix.conf - Secure configuration
# Only allow specific users/groups
user:admin allow nopass
group:wheel allow
group:sudo allow

# Deny all others by default
```

## Emergency Response

In case of a critical security incident:

1. **Immediate Action**: Disable Voix if necessary: `sudo chmod 000 /usr/bin/voix`
2. **Investigation**: Review logs in `/var/log/voix.log`
3. **Communication**: Contact daedaevibin@naver.com with details
4. **Recovery**: Follow incident response procedures

## Security Resources

- [OWASP Security Guidelines](https://owasp.org/)
- [CIS Security Benchmarks](https://www.cisecurity.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Contact

For security-related questions or concerns:

- **Email**: daedaevibin@naver.com
- **PGP Key**: Available upon request for encrypted communication

Thank you for helping keep Voix secure!
