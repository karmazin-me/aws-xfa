# Security Policy

## Important Notice

THIS SOFTWARE IS PROVIDED "AS IS" WITH NO SECURITY GUARANTEES OF ANY KIND.
See [DISCLAIMER.md](DISCLAIMER.md) and [LICENSE](LICENSE) for full terms.

The author(s) provide this software on a best-effort, volunteer basis.
**There is no obligation, express or implied, to fix any reported
vulnerability, to respond within any timeframe, or to maintain this software
at any security standard.**

## Threat Model

### What aws-xfa IS designed to do

- Simplify the AWS MFA credential workflow for individual developers
- Reduce manual `aws sts get-session-token` invocations
- Optionally retrieve TOTP codes from 1Password CLI
- Cache temporary session credentials locally in `~/.aws/credentials`

### What aws-xfa is NOT designed to protect against

- **Compromised local machine**: If an attacker has access to your local
  filesystem, shell, or memory, this tool cannot protect your credentials.
  This tool assumes no attackers on your local machine.
- **Malicious dependencies**: Supply chain attacks on Python packages,
  pip, or system libraries are outside the scope of this tool.
- **AWS account misconfiguration**: This tool does not validate or enforce
  IAM policies, permission boundaries, or account-level security settings.
- **Credential leakage via shell history**: Commands and environment
  variables may be logged by your shell. This tool does not scrub shell
  history.
- **Side-channel attacks**: Timing attacks, memory inspection, or other
  side-channel vectors are not mitigated.
- **Network-level attacks**: MITM, DNS hijacking, or TLS downgrade attacks
  on connections to AWS or 1Password APIs are handled by underlying system
  TLS libraries, not by this tool.

### Credential storage

- Long-term AWS credentials are stored in `~/.aws/credentials` in plaintext,
  consistent with AWS CLI's own behavior.
- Temporary session tokens are written to `~/.aws/credentials` in plaintext.
- File permissions are set to user-only (0600) on supported systems, but
  this is a best-effort measure, not a security guarantee.
- **Credentials may persist in memory** during the lifetime of the process.
- **Git history**: If your `~/.aws/` directory is accidentally committed to
  a git repository, credentials will be visible in the git history even
  after removal.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **DO NOT** open a public GitHub issue for security vulnerabilities.
2. Send a description of the vulnerability to: **[INSERT EMAIL OR USE
   GITHUB SECURITY ADVISORIES]**
3. Include steps to reproduce, if possible.
4. Allow reasonable time for assessment before public disclosure.

### What to expect

- Acknowledgment of receipt is provided on a best-effort basis.
- **There is no guaranteed response time, fix timeline, or SLA.**
- The author(s) may or may not issue a fix, at their sole discretion.
- The author(s) may or may not issue a CVE or security advisory.
- If you require guaranteed security response times, this software is
  not suitable for your use case.

## Supported Versions

Only the latest released version receives any security attention.
Previous versions are not supported, patched, or maintained.

| Version | Status            |
|---------|-------------------|
| Latest  | Best-effort only  |
| < Latest| Not supported     |

## Dependencies

This software depends on third-party packages. The author(s) are not
responsible for vulnerabilities in dependencies. Users should:

- Regularly update dependencies (`pip install --upgrade aws-xfa`)
- Monitor advisories for boto3, botocore, and other dependencies
- Use `pip audit` or similar tools to check for known vulnerabilities

## Security Best Practices (Your Responsibility)

- Rotate your AWS long-term credentials regularly
- Use the shortest practical session duration
- Enable CloudTrail logging on your AWS accounts
- Do not run this tool as root
- Do not store credentials in version-controlled directories
- Review the source code yourself if your threat model requires it
