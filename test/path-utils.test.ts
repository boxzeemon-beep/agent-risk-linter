import assert from "node:assert/strict";
import test from "node:test";
import { matchesAnyGlob } from "../src/path-utils.js";

test("glob matching handles recursive and basename patterns", () => {
  assert.equal(matchesAnyGlob("test/fixtures/a/SKILL.md", ["test/fixtures/**"]), true);
  assert.equal(matchesAnyGlob("nested/SKILL.md", ["SKILL.md"]), true);
  assert.equal(matchesAnyGlob("src/rules.ts", ["src/*.ts"]), true);
  assert.equal(matchesAnyGlob("src/nested/rules.ts", ["src/*.ts"]), false);
  assert.equal(matchesAnyGlob("vendor/", ["vendor/"]), true);
  assert.equal(matchesAnyGlob("src/index.ts", ["docs/**"]), false);
});
