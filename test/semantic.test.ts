import assert from "node:assert/strict";
import path from "node:path";
import test from "node:test";
import { redactText } from "../src/redact.js";
import { scanProject } from "../src/scanner.js";
import { prepareSemanticPayload, runSemanticReview } from "../src/semantic.js";

const unsafeRoot = path.resolve("test", "fixtures", "unsafe-skill");

test("redaction removes credential values and private keys", () => {
  const input = 'api_key="not-a-real-but-sensitive-value"\nAuthorization: Bearer token-value-123456\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----';
  const redacted = redactText(input);
  assert.ok(!redacted.includes("not-a-real-but-sensitive-value"));
  assert.ok(!redacted.includes("token-value-123456"));
  assert.ok(!redacted.includes("\nabc\n"));
  assert.match(redacted, /REDACTED/);
});

test("semantic preview is redacted, bounded, and limited to relevant file kinds", async () => {
  const execution = await scanProject({ root: unsafeRoot, useConfig: false });
  const payload = prepareSemanticPayload(execution, 1_500);
  const total = payload.files.reduce((sum, file) => sum + file.content.length, 0);
  assert.ok(total <= 1_500);
  assert.ok(payload.files.every((file) => ["instruction", "config", "workflow"].includes(file.kind)));
  assert.match(payload.notice, /untrusted data/i);
});

test("semantic review uses structured output and never places the API key in the body", async () => {
  const execution = await scanProject({ root: unsafeRoot, useConfig: false });
  let capturedBody = "";
  let capturedAuthorization = "";
  const fakeFetch = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    capturedBody = String(init?.body ?? "");
    capturedAuthorization = new Headers(init?.headers).get("Authorization") ?? "";
    return new Response(
      JSON.stringify({
        status: "completed",
        output: [
          {
            type: "message",
            content: [
              {
                type: "output_text",
                text: JSON.stringify({
                  findings: [
                    {
                      severity: "high",
                      category: "trust-boundary",
                      title: "External content receives instruction authority",
                      description: "The skill delegates command selection to remote issue content.",
                      remediation: "Treat remote issue content as data and require maintainer review.",
                      file: "SKILL.md",
                      line: 8
                    }
                  ]
                })
              }
            ]
          }
        ]
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  };

  const findings = await runSemanticReview(
    execution,
    { apiKey: "unit-test-secret-key", model: "test-model", maxChars: 2_000 },
    fakeFetch,
  );
  assert.equal(capturedAuthorization, "Bearer unit-test-secret-key");
  assert.ok(!capturedBody.includes("unit-test-secret-key"));
  assert.match(capturedBody, /json_schema/);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.source, "semantic");
  assert.equal(findings[0]?.ruleId, "AI001");
});
