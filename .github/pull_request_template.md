## What changed

Describe the user-visible behavior and the trust boundary affected.

## Evidence

- [ ] Tests cover the new behavior and likely false positives.
- [ ] `npm test` passes.
- [ ] `npm run self-scan` passes.
- [ ] `npm pack --dry-run` contains only intended files.
- [ ] Third-party actions and executable inputs are pinned or otherwise reviewed.
- [ ] No credentials, live malicious infrastructure, or executable malware fixtures are included.

## Security impact

Explain whether this changes file traversal, command detection, redaction, configuration suppressions, API payloads, workflow permissions, dependencies, or release artifacts.
