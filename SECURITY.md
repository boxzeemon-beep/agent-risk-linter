# Security policy

Agent Risk Linter processes untrusted instructions and security examples, so reports about parser behavior, redaction, path handling, CI boundaries, and release integrity are especially important.

## Supported versions

Until a stable 1.0 release, only the latest published minor release receives security fixes. Users should pin an immutable package version or action commit and upgrade after reviewing release notes.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/boxzeemon-beep/agent-risk-linter/security/advisories/new). Do not open a public issue containing:

- a working redaction bypass with real secret material;
- a path traversal or unexpected file-read proof of concept;
- a denial-of-service payload that could affect public automation;
- a release, npm, GitHub Action, or build-integrity compromise;
- exploit instructions against third-party systems.

If private reporting is unavailable, open a public issue that contains no exploit details and asks the maintainer to establish a private channel.

Include the affected version, platform, minimal reproduction, impact, and any safe mitigation. Replace credentials with inert placeholders and use reserved invalid domains.

## Disclosure

Please allow time to reproduce, patch, test, and publish before public disclosure. The maintainer will credit reporters who want attribution. Good-faith, authorized defensive testing is welcome; accessing data or systems without permission is not.

## Security design

The default scanner is offline and read-only, does not follow symlinks, does not execute target code, and has no runtime dependencies. Optional semantic review is a separate explicit path. See [THREAT_MODEL.md](THREAT_MODEL.md) for the complete model and limitations.
