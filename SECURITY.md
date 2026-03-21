# Security Policy

## Supported Versions

Currently, only the latest version of dig-rs is supported with security updates.

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in dig-rs, please report it responsibly.

### How to Report

1. **Do NOT** create a public issue or discuss the vulnerability publicly
2. Send an email to: tian.r.king@gmail.com
3. Include:
   - A description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested fixes (if available)

### What to Expect

- You will receive an acknowledgment within 48 hours
- We will investigate the issue and confirm the vulnerability
- We will provide a timeline for the fix
- We will coordinate the disclosure with you

### Disclosure Policy

- We aim to fix security vulnerabilities within 7 days of confirmation
- Updates will be released as soon as the fix is available
- Public disclosure will happen after the fix is released
- Credit will be given to reporters (unless you prefer to remain anonymous)

## Security Features

dig-rs includes several security features:

### Memory Safety
- Written in Rust for memory safety guarantees
- No buffer overflows or use-after-free vulnerabilities
- Safe handling of untrusted network input

### DNSSEC Validation
- Full DNSSEC validation support
- Chain of trust verification
- Support for all DNSSEC algorithms

### Secure Transports
- DNS-over-TLS (DoT) support
- DNS-over-HTTPS (DoH) support
- Certificate validation
- Optional certificate pinning

### TSIG Authentication
- Transaction SIGnature support
- Multiple HMAC algorithms (SHA256 recommended)
- Secure key handling

### Input Validation
- Strict DNS message parsing
- Protection against malformed responses
- Size limits on responses

### Privacy Features
- EDNS Padding support
- Client Subnet option control
- No telemetry or data collection

## Security Best Practices

### For Users

1. **Keep dig-rs updated**: Always use the latest version
2. **Use secure transports**: Prefer DoT/DoH when available
3. **Verify DNSSEC**: Enable DNSSEC validation when possible
4. **Use trusted resolvers**: Query only trusted DNS servers
5. **Protect TSIG keys**: Never commit TSIG keys to version control

### For Developers

1. **Follow security guidelines**: Read this SECURITY.md thoroughly
2. **Audit dependencies**: Regularly review dependency versions
3. **Use safe Rust**: Avoid `unsafe` code unless absolutely necessary
4. **Test security features**: Run tests with security features enabled
5. **Report vulnerabilities**: Follow the disclosure policy above

## Dependency Security

We use automated security auditing:

- **cargo-audit**: Checks for known vulnerabilities in dependencies
- **cargo-deny**: Enforces license and dependency policies
- **GitHub Dependabot**: Automated dependency updates

Security audits run on every pull request and release.

## Security Audits

| Date | Version | Auditor | Report |
|------|---------|---------|--------|
| TBD  | 0.1.0   | Pending | TBD    |

## Contact

For security-related questions that don't involve vulnerability disclosure, please contact:

- **Email**: tian.r.king@gmail.com
- **GitHub Issues**: https://github.com/tianrking/dig-rs/issues
