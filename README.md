# Agent Risk Linter

[![CI](https://github.com/boxzeemon-beep/agent-risk-linter/actions/workflows/ci.yml/badge.svg)](https://github.com/boxzeemon-beep/agent-risk-linter/actions/workflows/ci.yml)
[![CodeQL](https://github.com/boxzeemon-beep/agent-risk-linter/actions/workflows/codeql.yml/badge.svg)](https://github.com/boxzeemon-beep/agent-risk-linter/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Agent Risk Linter is an offline-first security linter for AI agent instruction packages. It scans Codex and other Agent Skills, `AGENTS.md` or `CLAUDE.md`, MCP configuration, plugin manifests, related scripts, package hooks, and GitHub Actions without executing target code.

Status: **alpha**. The rule set is useful today, but findings are heuristic and require maintainer review.

## Why this exists

Agent packages are not ordinary documentation. A short instruction file can influence an agent's shell commands, filesystem changes, network requests, credentials, tool calls, and code modifications. A contributed Skill or MCP configuration can therefore create a supply-chain boundary even when it contains little conventional source code.

Agent Risk Linter makes those behaviors reviewable before installation or merge. It reports exact files and lines, produces SARIF for GitHub code scanning, and keeps its core scan local and deterministic.

## Quick start

The npm package has not been published yet. Until the first npm release, build from a reviewed source checkout:

```sh
git clone https://github.com/boxzeemon-beep/agent-risk-linter.git
cd agent-risk-linter
git checkout 1bb4e3b5d0353feec9a11d5b7a998e4aab054d8f
npm ci --ignore-scripts
npm run build
node dist/src/cli.js scan .
```

After `0.1.0` is published to npm, the pinned commands will be:

```sh
npx --yes agent-risk-linter@0.1.0 scan .
npm install --save-dev agent-risk-linter@0.1.0
npx agent-risk-linter scan .
```

The default exit threshold is `high`. Use `--fail-on none` during initial review so all findings can be evaluated without stopping the workflow.

## What it detects

| Surface | Examples of reviewed risk |
| --- | --- |
| Agent instructions | hierarchy overrides, concealment, approval or sandbox bypass, authority delegated to external content |
| Shell and filesystem | remote-to-shell pipelines, dynamic evaluation, encoded execution, recursive deletion, privilege broadening |
| Credentials and network | sensitive credential stores, environment enumeration, hardcoded secrets, credential-bearing requests, reverse shells |
| Package supply chain | install lifecycle hooks and dependencies that bypass normal registry versioning |
| GitHub Actions | mutable action references, `write-all`, privileged PR events, checkout of contributor-controlled code |
| MCP configuration | unencrypted remote endpoints and shell-wrapped server commands |
| Skill metadata | missing `name` or `description` fields that make activation less predictable |

List every rule or explain one rule:

```sh
agent-risk-linter rules
agent-risk-linter rules CI003
agent-risk-linter rules --json
```

## Security properties of the scanner

- Zero runtime npm dependencies.
- Does not execute scripts, package hooks, MCP servers, or target commands.
- Does not follow symbolic links.
- Skips binary-looking files and common generated or dependency directories.
- Caps individual file size and total file count.
- Redacts credential-like material again before terminal, JSON, SARIF, or semantic-review output.
- Makes no network request during a normal scan.
- Requires an explicit `--semantic` flag before any content is sent to OpenAI.

See [THREAT_MODEL.md](THREAT_MODEL.md) for trust boundaries and known limitations.

## CLI

```text
agent-risk-linter scan [path] [options]

--format text|json|sarif
--output <file>
--fail-on low|medium|high|critical|none
--config <file>
--no-config
--ignore <glob>
--disable-rule <id>
--max-file-bytes <number>
--max-files <number>
--semantic
--model <name>
--max-semantic-chars <number>
--semantic-preview <file>
```

Exit code `0` means the scan completed below the configured threshold, `1` means a finding met the threshold, and `2` means the target, configuration, API request, or runtime failed.

### Scan one file

```sh
agent-risk-linter scan path/to/SKILL.md --fail-on none
```

### Generate SARIF

```sh
agent-risk-linter scan . --format sarif --output agent-risk-linter.sarif
```

## Configuration

Create `.agent-risk-linter.json` at the scan root:

```json
{
  "$schema": "./schema/config.schema.json",
  "failOn": "high",
  "ignore": ["test/fixtures/**"],
  "disableRules": [],
  "overrides": [
    {
      "files": ["docs/security-examples.md"],
      "disableRules": ["SHELL001"]
    }
  ],
  "maxFileBytes": 1000000,
  "maxFiles": 20000,
  "semantic": {
    "model": "gpt-5.6-luna",
    "maxChars": 30000
  }
}
```

Suppressions are intentionally centralized in configuration instead of being trusted from inline comments inside the scanned file. Treat every suppression change as a security-relevant code review item.

## GitHub Action

Pin this action and all other actions to reviewed immutable commit SHAs. Replace the placeholder below with the commit for the release you reviewed:

```yaml
name: Agent instruction security
on:
  pull_request:
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09
      - id: agent-risk
        uses: boxzeemon-beep/agent-risk-linter@1bb4e3b5d0353feec9a11d5b7a998e4aab054d8f
        with:
          fail-on: high
      - if: always()
        uses: github/codeql-action/upload-sarif@d6317709a54fd87078d323eeb0e48ec331c8e621
        with:
          sarif_file: agent-risk-linter.sarif
```

The JavaScript action performs static scanning only. It does not accept an API key or enable semantic review, avoiding secret exposure while processing untrusted pull requests.

## Codex Skill

The repository includes a repo-scoped Skill at [`.agents/skills/scan-agent-risk`](.agents/skills/scan-agent-risk/SKILL.md). Codex discovers repository Skills from `.agents/skills` according to the [official Skill documentation](https://learn.chatgpt.com/docs/build-skills).

Invoke it explicitly with:

```text
$scan-agent-risk audit this repository's agent instructions and MCP configuration
```

The Skill tells the agent to keep scanned content untrusted, avoid executing target code, run the linter, verify evidence, and distinguish static from optional semantic findings.

## Optional OpenAI semantic review

Static scanning is the default. Semantic review is intended for ambiguous instruction chains that require context beyond deterministic patterns.

1. Set `OPENAI_API_KEY` using your operating system or CI secret manager; never store it in the repository.
2. Inspect the exact redacted payload without a network request:

   ```sh
   agent-risk-linter scan . --semantic-preview semantic-preview.json --fail-on none
   ```

3. After confirming the payload, opt in:

   ```sh
   agent-risk-linter scan . --semantic --fail-on none
   ```

Semantic review sends only redacted, bounded instruction/configuration/workflow text, uses the OpenAI Responses API with structured output, and sets `store: false`. It never sends the API key in the request body. Model output is untrusted analysis and must be verified before remediation.

The integration follows the [OpenAI Responses API](https://developers.openai.com/api/docs/guides/text) and [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs) documentation.

## Scope and limitations

Agent Risk Linter is not a malware sandbox, dependency resolver, secret revocation service, full SAST engine, or proof of exploitability. It does not inspect binaries or execute code. A clean result means no enabled rule matched the files that were read; it does not prove the package is safe.

False positives and missed cases are expected during the alpha. Please use the issue templates to submit minimal, inert examples. Do not post real credentials or working malicious infrastructure.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports belong in [private vulnerability reporting](https://github.com/boxzeemon-beep/agent-risk-linter/security/advisories/new), not public issues.

## License

Apache License 2.0. See [LICENSE](LICENSE).
