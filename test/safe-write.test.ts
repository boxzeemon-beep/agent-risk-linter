import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveOutputWithin, safeWriteText } from "../src/safe-write.js";

test("safeWriteText writes and replaces regular files", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agent-risk-output-"));
  try {
    const output = path.join(directory, "report.json");
    await safeWriteText(output, "first");
    await safeWriteText(output, "second");
    assert.equal(await readFile(output, "utf8"), "second");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("resolveOutputWithin rejects paths outside the workspace", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "agent-risk-workspace-"));
  try {
    await assert.rejects(resolveOutputWithin(directory, path.join("..", "outside.sarif")), /inside the GitHub workspace/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("safeWriteText refuses a symbolic-link destination", async (context) => {
  if (process.platform === "win32") {
    context.skip("Creating symlinks commonly requires Windows developer mode.");
    return;
  }
  const directory = await mkdtemp(path.join(os.tmpdir(), "agent-risk-output-link-"));
  try {
    const target = path.join(directory, "target.txt");
    const link = path.join(directory, "report.txt");
    await writeFile(target, "preserve", "utf8");
    await symlink(target, link);
    await assert.rejects(safeWriteText(link, "overwrite"), /symbolic link/);
    assert.equal(await readFile(target, "utf8"), "preserve");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
