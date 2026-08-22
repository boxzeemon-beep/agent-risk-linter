# Changelog

All notable changes are documented here. The project follows Semantic Versioning after the initial alpha series.

## 0.1.0 - Unreleased

- Add offline scanning for agent instructions, scripts, MCP configuration, package manifests, and GitHub Actions.
- Add 28 deterministic rules across prompt injection, authorization, command execution, filesystem, credentials, network egress, supply chain, CI, MCP, obfuscation, and Skill metadata, including detection of Codex lifecycle hooks and static MCP credential headers.
- Add text, JSON, and SARIF output with credential redaction.
- Replace private-key redaction backtracking with a linear-time scan and adversarial regression coverage.
- Add a zero-runtime-dependency CLI and JavaScript GitHub Action.
- Add an opt-in, redacted OpenAI Responses API semantic review and offline payload preview.
- Add the `scan-agent-risk` Codex Skill, tests, CodeQL, threat model, and security disclosure process.
