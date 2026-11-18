# Security Policy

## Reporting a vulnerability
Please **do not open a public issue**. Use GitHub's "Report a vulnerability" (Security tab → Advisories) on this repository, or email the maintainer address listed in `package.json`. Expect an acknowledgement within 72 hours.

## Scope
- Secret leakage in output or logs
- Code execution outside `--introspect`
- Path traversal or unsafe file handling in discovery
- False negatives for critical rules are bugs, not vulnerabilities, so open a normal issue.

## Supported versions
The latest minor release receives fixes.
