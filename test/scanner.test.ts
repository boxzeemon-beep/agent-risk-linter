import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanProject } from "../src/scanner.js";

const fixture = (...parts: string[]): string => path.resolve("test", "fixtures", ...parts);

test("safe skill has no findings", async () => {
  const execution = await scanProject({ root: fixture("safe-skill"), useConfig: false });
  assert.equal(execution.result.findings.length, 0);
  assert.equal(execution.result.filesScanned, 1);
});

test("unsafe skill exposes agent, shell, filesystem, network, MCP, supply-chain, and CI risks", async () => {
  const execution = await scanProject({ root: fixture("unsafe-skill"), useConfig: false });
  const ids = new Set(execution.result.findings.map((finding) => finding.ruleId));
  for (const expected of ["AGENT001", "AGENT002", "AGENT003", "SHELL001", "FS001", "CRED002", "NET001", "PRIV001", "MCP001", "MCP002", "SC001", "SC002", "SC003", "CI001", "CI002", "CI003"]) {
    assert.ok(ids.has(expected), `expected ${expected}; received ${[...ids].join(", ")}`);
  }
});

test("single files can be scanned", async () => {
  const execution = await scanProject({ root: fixture("unsafe-skill", "SKILL.md"), useConfig: false });
  assert.equal(execution.result.filesScanned, 1);
  assert.ok(execution.result.findings.some((finding) => finding.ruleId === "SHELL001"));
});

test("configuration can ignore paths and apply auditable rule overrides", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agent-risk-linter-"));
  try {
    await writeFile(path.join(directory, "SKILL.md"), await readFile(fixture("unsafe-skill", "SKILL.md"), "utf8"), "utf8");
    await writeFile(
      path.join(directory, ".agent-risk-linter.json"),
      JSON.stringify({ overrides: [{ files: ["SKILL.md"], disableRules: ["SHELL001", "FS001", "FS002"] }] }),
      "utf8",
    );
    const execution = await scanProject({ root: directory });
    const ids = new Set(execution.result.findings.map((finding) => finding.ruleId));
    assert.ok(!ids.has("SHELL001"));
    assert.ok(!ids.has("FS001"));
    assert.ok(ids.has("AGENT001"));
    assert.ok(execution.result.diagnostics.some((diagnostic) => diagnostic.code === "RULE_SUPPRESSIONS_ACTIVE"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("untrusted configuration cannot raise hard resource limits", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agent-risk-linter-limit-"));
  try {
    await writeFile(path.join(directory, "SKILL.md"), await readFile(fixture("safe-skill", "SKILL.md"), "utf8"), "utf8");
    await writeFile(
      path.join(directory, ".agent-risk-linter.json"),
      JSON.stringify({ maxFileBytes: 999_999_999, maxFiles: 999_999_999, semantic: { maxChars: 999_999_999 } }),
      "utf8",
    );
    const execution = await scanProject({ root: directory });
    assert.equal(execution.config.maxFileBytes, 10_000_000);
    assert.equal(execution.config.maxFiles, 100_000);
    assert.equal(execution.config.semantic.maxChars, 200_000);
    assert.ok(execution.result.diagnostics.filter((diagnostic) => diagnostic.code === "CONFIG_CLAMPED").length >= 3);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("scanner findings redact a detected credential value", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agent-risk-linter-redact-"));
  const secret = "sensitive-value-that-must-not-appear";
  try {
    await writeFile(path.join(directory, "settings.json"), JSON.stringify({ api_key: secret }), "utf8");
    const execution = await scanProject({ root: directory, useConfig: false });
    assert.ok(execution.result.findings.some((finding) => finding.ruleId === "CRED003"));
    assert.ok(!JSON.stringify(execution.result).includes(secret));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("bidirectional controls are reported and removed from output", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agent-risk-linter-bidi-"));
  try {
    await writeFile(path.join(directory, "SKILL.md"), `---\nname: bidi-test\ndescription: inert fixture\n---\nVisible \u202Ehidden`, "utf8");
    const execution = await scanProject({ root: directory, useConfig: false });
    assert.ok(execution.result.findings.some((finding) => finding.ruleId === "OBF002"));
    assert.ok(!JSON.stringify(execution.result).includes("\u202E"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("an explicitly missing configuration fails closed", async () => {
  await assert.rejects(
    scanProject({ root: fixture("safe-skill"), configPath: "missing-config.json" }),
    /Could not load configuration/,
  );
});

test("scanner does not follow symbolic links", async (context) => {
  if (process.platform === "win32") {
    context.skip("Creating symlinks commonly requires Windows developer mode.");
    return;
  }
  const directory = await mkdtemp(path.join(os.tmpdir(), "agent-risk-linter-link-"));
  try {
    const { symlink } = await import("node:fs/promises");
    await symlink(fixture("unsafe-skill", "SKILL.md"), path.join(directory, "linked.md"));
    const execution = await scanProject({ root: directory, useConfig: false });
    assert.equal(execution.result.filesScanned, 0);
    assert.ok(execution.result.diagnostics.some((diagnostic) => diagnostic.code === "SYMLINK_SKIPPED"));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
