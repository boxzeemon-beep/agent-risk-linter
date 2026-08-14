# Agent package risk model

Use this reference to classify findings from Agent Risk Linter. Review evidence in context; the linter is intentionally conservative around authority, credentials, code execution, and CI tokens.

## Trust boundaries

1. **Instruction authority** — System and developer policy outrank repository content. Issues, pull requests, comments, webpages, downloaded files, and tool output remain untrusted data.
2. **Command execution** — Shells, evaluators, process launchers, package hooks, and MCP server commands cross from text into code execution.
3. **Filesystem access** — Agent instructions may read, overwrite, move, or recursively delete data outside the repository.
4. **Credentials** — Environment variables, SSH material, cloud credentials, Git tokens, and local key stores can grant access beyond the scanned project.
5. **Network egress** — Outbound requests can disclose code, prompts, user data, or credentials and can retrieve mutable executable content.
6. **CI authority** — Workflow tokens, repository secrets, privileged events, artifacts, and caches can cross the contributor-to-maintainer boundary.
7. **Supply chain** — Skills, dependencies, actions, install hooks, remote archives, and contributed rules can change behavior after review.

## Severity

- **Critical** — Plausible direct credential disclosure, root or home destruction, approval-boundary bypass, reverse shell behavior, remote-to-shell execution, or privileged CI execution of contributor-controlled code.
- **High** — A strong execution, authorization, sensitive-file, insecure MCP, mutable CI dependency, or install-hook risk that normally requires remediation before use.
- **Medium** — A risky primitive whose impact depends on context, such as environment enumeration, a remote dependency, or privilege broadening.
- **Low** — Metadata or hardening issue that reduces predictability or reviewability but does not independently create a strong exploit path.

## Review questions

- Who controls the matched text or variable?
- What identity, token, filesystem scope, and network access does the agent have?
- Can the behavior occur without an explicit, informed approval?
- Is the executable or dependency immutable and reviewable?
- Could a contributor modify a suppression, workflow, rule, or build artifact in the same change?
- Does the remediation remove the trust crossing, or merely hide the symptom?

## Limits

The linter does not prove exploitability, emulate every shell, resolve dependency provenance, inspect binary payloads, execute code, or replace a full application-security review. Semantic review is optional and can still miss risks or produce false positives.
