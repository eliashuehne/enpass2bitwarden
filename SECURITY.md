# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| latest release | ✅ |
| older releases | ❌ (upgrade) |

## Reporting a vulnerability

This tool handles password-manager vaults, so reports are taken seriously.

**Do NOT open a public GitHub issue for security vulnerabilities** — a public
issue may expose attack details before a fix exists.

Instead, use GitHub's private vulnerability reporting:
**Security tab → Report a vulnerability**, or email the owner via the email
address on the GitHub profile.

You will get a response within 7 days. Please include:

- Version of `enpass2bitwarden` and OS
- Steps to reproduce or a proof of concept
- Impact assessment (what an attacker could do)

## Scope

In scope: anything that could lead to decryption of vault data without the
master password, leakage of decrypted secrets (memory, temp files, logs),
or injection through malicious vault contents.

Out of scope: vulnerabilities in Enpass or Bitwarden themselves — report
those to their respective vendors.
