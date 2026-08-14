import { createHash } from "node:crypto";
import { lstat } from "node:fs/promises";
import path from "node:path";
import { collectFiles } from "./files.js";
import { HARD_LIMITS, loadConfig } from "./config.js";
import { matchesAnyGlob, toPosixPath } from "./path-utils.js";
import { redactAndSanitize } from "./redact.js";
import { RULES } from "./rules.js";
import { SEVERITY_RANK } from "./types.js";
import { VERSION } from "./version.js";
function locationAt(content, index) {
    const safeIndex = Math.max(0, Math.min(index, content.length));
    const before = content.slice(0, safeIndex);
    const line = before.split("\n").length;
    const lastNewline = before.lastIndexOf("\n");
    return { line, column: safeIndex - lastNewline };
}
function excerptAt(content, index) {
    const safeIndex = Math.max(0, Math.min(index, content.length));
    const start = content.lastIndexOf("\n", safeIndex - 1) + 1;
    const nextNewline = content.indexOf("\n", safeIndex);
    const end = nextNewline === -1 ? content.length : nextNewline;
    const line = content.slice(start, end).trim();
    const compact = line.length > 240 ? `${line.slice(0, 237)}...` : line;
    return redactAndSanitize(compact);
}
function fingerprint(file, rule, match) {
    const matched = file.content.slice(match.index, match.index + match.length);
    const normalized = redactAndSanitize(matched).replace(/\s+/g, " ").trim();
    return createHash("sha256").update(`${file.relativePath}\0${rule.id}\0${normalized}`).digest("hex");
}
function findingFromMatch(file, rule, match) {
    const start = locationAt(file.content, match.index);
    const end = locationAt(file.content, match.index + Math.max(match.length, 1));
    return {
        ruleId: rule.id,
        title: rule.title,
        description: match.message ? `${rule.description} (${redactAndSanitize(match.message)})` : rule.description,
        remediation: rule.remediation,
        severity: rule.severity,
        category: rule.category,
        source: "static",
        file: file.relativePath,
        line: start.line,
        column: start.column,
        endLine: end.line,
        endColumn: end.column,
        excerpt: excerptAt(file.content, match.index),
        fingerprint: fingerprint(file, rule, match),
    };
}
function disabledRulesForFile(config, relativePath, commandLineDisabled) {
    const disabled = new Set([...config.disableRules, ...commandLineDisabled].map((id) => id.toUpperCase()));
    for (const override of config.overrides) {
        if (matchesAnyGlob(relativePath, override.files)) {
            for (const ruleId of override.disableRules)
                disabled.add(ruleId.toUpperCase());
        }
    }
    return disabled;
}
function summarize(findings) {
    const summary = { critical: 0, high: 0, medium: 0, low: 0, total: findings.length };
    for (const finding of findings)
        summary[finding.severity] += 1;
    return summary;
}
function deduplicate(findings) {
    const seen = new Set();
    return findings.filter((finding) => {
        const key = `${finding.ruleId}\0${finding.file}\0${finding.line}\0${finding.column}`;
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
}
export async function scanProject(options) {
    const target = path.resolve(options.root);
    const stats = await lstat(target);
    if (stats.isSymbolicLink())
        throw new Error("Refusing to follow a symbolic-link scan target.");
    const configRoot = stats.isDirectory() ? target : path.dirname(target);
    const loaded = await loadConfig(configRoot, options.configPath, options.useConfig ?? true);
    const config = {
        ...loaded.config,
        ignore: [...loaded.config.ignore, ...(options.ignore ?? [])],
        disableRules: [...loaded.config.disableRules],
        maxFileBytes: Math.min(options.maxFileBytes ?? loaded.config.maxFileBytes, HARD_LIMITS.maxFileBytes),
        maxFiles: Math.min(options.maxFiles ?? loaded.config.maxFiles, HARD_LIMITS.maxFiles),
        semantic: { ...loaded.config.semantic },
    };
    const collection = await collectFiles({
        root: target,
        ignore: config.ignore,
        maxFileBytes: config.maxFileBytes,
        maxFiles: config.maxFiles,
    });
    const diagnostics = [...loaded.diagnostics, ...collection.diagnostics];
    const knownRuleIds = new Set(RULES.map((rule) => rule.id));
    const requestedDisabled = [...config.disableRules, ...(options.disabledRules ?? [])].map((id) => id.toUpperCase());
    const allConfiguredDisabled = [
        ...requestedDisabled,
        ...config.overrides.flatMap((override) => override.disableRules.map((id) => id.toUpperCase())),
    ];
    for (const ruleId of allConfiguredDisabled) {
        if (!knownRuleIds.has(ruleId))
            diagnostics.push({ level: "warning", code: "UNKNOWN_RULE", message: `Disabled rule does not exist: ${ruleId}` });
    }
    if (requestedDisabled.length > 0 || config.overrides.length > 0) {
        diagnostics.push({
            level: "info",
            code: "RULE_SUPPRESSIONS_ACTIVE",
            message: `${requestedDisabled.length} global rule suppression(s) and ${config.overrides.length} path override(s) are active. Review suppression changes as security-sensitive.`,
        });
    }
    const findings = [];
    for (const file of collection.files) {
        const disabled = disabledRulesForFile(config, file.relativePath, options.disabledRules ?? []);
        for (const rule of RULES) {
            if (!rule.appliesTo.includes(file.kind) || disabled.has(rule.id))
                continue;
            for (const match of rule.detect({ file }))
                findings.push(findingFromMatch(file, rule, match));
        }
    }
    const sorted = deduplicate(findings).sort((left, right) => {
        const severity = SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity];
        if (severity !== 0)
            return severity;
        const file = left.file.localeCompare(right.file);
        if (file !== 0)
            return file;
        return left.line - right.line || left.column - right.column || left.ruleId.localeCompare(right.ruleId);
    });
    const displayRoot = stats.isDirectory() ? target : target;
    return {
        result: {
            schemaVersion: "1.0",
            tool: { name: "agent-risk-linter", version: VERSION },
            root: toPosixPath(displayRoot),
            generatedAt: new Date().toISOString(),
            filesScanned: collection.files.length,
            bytesScanned: collection.files.reduce((total, file) => total + file.bytes, 0),
            findings: sorted,
            diagnostics,
            summary: summarize(sorted),
        },
        files: collection.files,
        config,
    };
}
export function addFindings(execution, additional) {
    const findings = deduplicate([...execution.result.findings, ...additional]).sort((left, right) => SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity] || left.file.localeCompare(right.file) || left.line - right.line);
    return {
        ...execution,
        result: {
            ...execution.result,
            findings,
            summary: summarize(findings),
        },
    };
}
//# sourceMappingURL=scanner.js.map