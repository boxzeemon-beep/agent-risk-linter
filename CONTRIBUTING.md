# Contributing

Contributions should improve a real agent-security workflow and include evidence that the change does not create avoidable execution or supply-chain risk.

## Development

Requirements: Node.js 20 or later and npm.

```sh
npm ci --ignore-scripts
npm test
npm run self-scan
npm pack --dry-run
```

Before opening a pull request, inspect `git diff`, including generated `dist/` changes. Do not commit dependency directories, local reports, API keys, or semantic-preview files.

## Rule contributions

A rule pull request should include:

- a concise threat boundary and realistic impact;
- an inert positive fixture that triggers the rule;
- a safe negative fixture that does not trigger;
- tests for common formatting variants;
- a specific remediation that removes or narrows the boundary;
- an explanation of expected false positives.

Use reserved invalid domains and placeholders. Never add real credentials, live malicious infrastructure, destructive test automation, or code that executes a fixture. Prefer a narrower high-confidence rule to a broad noisy expression.

Rule IDs are grouped by surface: `AGENT`, `SHELL`, `FS`, `CRED`, `NET`, `OBF`, `PRIV`, `SC`, `CI`, `MCP`, and `META`. Ask in an issue before introducing a new family.

## Security-sensitive changes

Changes to file traversal, redaction, configuration suppressions, semantic-review payloads, GitHub workflows, release automation, or compiled action output require focused tests and threat-model review. Pin third-party actions to full commit SHAs.

## Issues and pull requests

- Use the false-positive template for noisy rules and include the smallest safe sample.
- Use the rule-request template for missed patterns.
- Keep pull requests focused and describe user-visible behavior.
- Add or update tests for every behavior change.
- Do not use public issues for vulnerabilities; follow [SECURITY.md](SECURITY.md).

By participating, follow the [Code of Conduct](CODE_OF_CONDUCT.md).
