import { appendFile } from "node:fs/promises";
import { renderResult } from "./reporters.js";
import { resolveOutputWithin, safeWriteText } from "./safe-write.js";
import { scanProject } from "./scanner.js";
import { SEVERITY_RANK } from "./types.js";
function input(name, fallback) {
    return process.env[`INPUT_${name.toUpperCase().replaceAll("_", "-")}`]?.trim() || fallback;
}
function escapeCommandData(value) {
    return value.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
}
function escapeCommandProperty(value) {
    return escapeCommandData(value).replaceAll(":", "%3A").replaceAll(",", "%2C");
}
async function setOutput(name, value) {
    const outputFile = process.env.GITHUB_OUTPUT;
    if (!outputFile)
        return;
    await appendFile(outputFile, `${name}=${value}\n`, "utf8");
}
async function main() {
    const root = input("path", ".");
    const failOn = input("fail-on", "high");
    const output = input("output", "agent-risk-linter.sarif");
    const config = input("config", "");
    if (failOn !== "none" && !(failOn in SEVERITY_RANK))
        throw new Error(`Invalid fail-on value: ${failOn}`);
    const execution = await scanProject({ root, configPath: config || undefined });
    const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
    const resolvedOutput = await resolveOutputWithin(workspace, output);
    await safeWriteText(resolvedOutput, renderResult(execution.result, "sarif"));
    for (const finding of execution.result.findings.slice(0, 20)) {
        const level = finding.severity === "critical" || finding.severity === "high" ? "error" : "warning";
        const properties = `file=${escapeCommandProperty(finding.file)},line=${finding.line},col=${finding.column},title=${escapeCommandProperty(`${finding.ruleId}: ${finding.title}`)}`;
        process.stdout.write(`::${level} ${properties}::${escapeCommandData(finding.description)}\n`);
    }
    for (const diagnostic of execution.result.diagnostics.filter((entry) => entry.level === "warning" || entry.code === "RULE_SUPPRESSIONS_ACTIVE")) {
        process.stdout.write(`::notice title=${escapeCommandProperty(diagnostic.code)}::${escapeCommandData(diagnostic.message)}\n`);
    }
    await setOutput("results-file", output);
    await setOutput("finding-count", String(execution.result.summary.total));
    await setOutput("critical-count", String(execution.result.summary.critical));
    await setOutput("high-count", String(execution.result.summary.high));
    if (failOn !== "none" && execution.result.findings.some((finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[failOn])) {
        process.exitCode = 1;
    }
}
main().catch((error) => {
    process.stderr.write(`agent-risk-linter action: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
});
//# sourceMappingURL=action.js.map