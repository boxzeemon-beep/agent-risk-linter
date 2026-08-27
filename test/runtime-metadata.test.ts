import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

test("runtime metadata excludes EOL Node.js 20 and tests current patch releases", async () => {
  const packageJson = JSON.parse(await readFile(path.resolve("package.json"), "utf8")) as {
    engines?: { node?: string };
  };
  const actionMetadata = await readFile(path.resolve("action.yml"), "utf8");
  const ciWorkflow = await readFile(path.resolve(".github", "workflows", "ci.yml"), "utf8");

  assert.equal(packageJson.engines?.node, ">=22");
  assert.match(actionMetadata, /^\s*using:\s*node24\s*$/mu);
  assert.match(ciWorkflow, /^\s*node:\s*\["22",\s*"24",\s*"26"\]\s*$/mu);
  assert.match(ciWorkflow, /^\s*check-latest:\s*true\s*$/mu);
  assert.doesNotMatch(ciWorkflow, /^\s*node:\s*\[[^\]]*"20"/mu);
});
