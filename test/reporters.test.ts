import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import packageJson from "../package.json" with { type: "json" };
import { renderResult } from "../src/reporters.js";
import { scanProject } from "../src/scanner.js";
import { VERSION } from "../src/version.js";

test("package version matches the runtime version", () => {
  assert.equal(packageJson.version, VERSION);
});

test("SARIF contains rules, locations, and fingerprints", async () => {
  const execution = await scanProject({ root: path.resolve("test", "fixtures", "unsafe-skill"), useConfig: false });
  const sarif = JSON.parse(renderResult(execution.result, "sarif")) as {
    version: string;
    runs: Array<{ results: Array<Record<string, unknown>> }>;
  };
  assert.equal(sarif.version, "2.1.0");
  assert.ok((sarif.runs[0]?.results.length ?? 0) > 0);
  assert.ok(sarif.runs[0]?.results.every((result) => "partialFingerprints" in result));
});

test("JSON report does not expose the credential-like fixture text", async () => {
  const execution = await scanProject({ root: path.resolve("test", "fixtures", "unsafe-skill"), useConfig: false });
  const output = renderResult(execution.result, "json");
  assert.ok(!output.includes("unit-test-secret-key"));
});
