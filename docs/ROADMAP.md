# Roadmap

The roadmap is organized around measurable maintenance work rather than promised dates. Priorities will change in response to real false positives, missed cases, and contributor feedback.

## 0.1 — Publishable alpha

- Offline read-only scanner with 26 built-in rules.
- Text, JSON, and SARIF output.
- npm CLI, GitHub Action, and repo-scoped Codex Skill.
- Optional redacted OpenAI semantic review.
- Tests, CodeQL, threat model, security policy, and contribution workflow.

## 0.2 — Evidence and precision

- Expand the inert corpus with community-submitted safe and unsafe samples.
- Add multi-signal rules that join instruction authority with shell, credentials, network, or filesystem access.
- Report configuration and rule-diff risk during pull-request review.
- Measure per-rule precision on the public corpus and publish the methodology.
- Add stable machine-readable rule metadata and documentation generation.

## 0.3 — Ecosystem coverage

- Validate additional Agent Skill and plugin manifest variants.
- Add deeper MCP command, environment, transport, and permission analysis.
- Add lockfile and release-provenance checks without executing package managers.
- Support safe baselines that cannot be silently authored by the scanned file.

## 1.0 — Stable policy surface

- Stabilize configuration and JSON schemas.
- Document compatibility and deprecation policy.
- Establish reproducible release verification for npm and the GitHub Action.
- Publish a maintained rule-quality dashboard based on public, inert fixtures.

## Non-goals

- Malware detonation or offensive exploitation.
- Automatic execution of target code.
- Automatic fixes or merges based only on static or model findings.
- Replacing general SAST, dependency advisory, or container security tools.
