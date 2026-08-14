import { readFile } from "node:fs/promises";
import path from "node:path";
import { SEVERITIES } from "./types.js";
export const DEFAULT_CONFIG = {
    failOn: "high",
    ignore: [],
    disableRules: [],
    overrides: [],
    maxFileBytes: 1_000_000,
    maxFiles: 20_000,
    semantic: {
        model: "gpt-5.6-luna",
        maxChars: 30_000,
    },
};
export const HARD_LIMITS = {
    maxFileBytes: 10_000_000,
    maxFiles: 100_000,
    maxSemanticChars: 200_000,
};
function isObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function stringArray(value, field, diagnostics) {
    if (value === undefined)
        return [];
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
        diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: `${field} must be an array of strings.` });
        return [];
    }
    return [...new Set(value)];
}
function positiveInteger(value, fallback, field, diagnostics, maximum = Number.MAX_SAFE_INTEGER) {
    if (value === undefined)
        return fallback;
    if (!Number.isInteger(value) || Number(value) <= 0) {
        diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: `${field} must be a positive integer.` });
        return fallback;
    }
    if (Number(value) > maximum) {
        diagnostics.push({ level: "warning", code: "CONFIG_CLAMPED", message: `${field} was clamped to the hard limit of ${maximum}.` });
        return maximum;
    }
    return Number(value);
}
function parseOverrides(value, diagnostics) {
    if (value === undefined)
        return [];
    if (!Array.isArray(value)) {
        diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: "overrides must be an array." });
        return [];
    }
    const overrides = [];
    for (const [index, entry] of value.entries()) {
        if (!isObject(entry)) {
            diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: `overrides[${index}] must be an object.` });
            continue;
        }
        const files = stringArray(entry.files, `overrides[${index}].files`, diagnostics);
        const disableRules = stringArray(entry.disableRules, `overrides[${index}].disableRules`, diagnostics);
        if (files.length > 0 && disableRules.length > 0)
            overrides.push({ files, disableRules });
    }
    return overrides;
}
function parseConfig(value, diagnostics) {
    if (!isObject(value)) {
        diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: "Configuration root must be an object." });
        return structuredClone(DEFAULT_CONFIG);
    }
    const known = new Set(["$schema", "failOn", "ignore", "disableRules", "overrides", "maxFileBytes", "maxFiles", "semantic"]);
    for (const key of Object.keys(value)) {
        if (!known.has(key)) {
            diagnostics.push({ level: "info", code: "CONFIG_UNKNOWN_KEY", message: `Unknown configuration key: ${key}` });
        }
    }
    let failOn = DEFAULT_CONFIG.failOn;
    if (value.failOn !== undefined) {
        if (value.failOn === "none" || (typeof value.failOn === "string" && SEVERITIES.includes(value.failOn))) {
            failOn = value.failOn;
        }
        else {
            diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: "failOn must be low, medium, high, critical, or none." });
        }
    }
    let semantic = { ...DEFAULT_CONFIG.semantic };
    if (value.semantic !== undefined) {
        if (isObject(value.semantic)) {
            if (typeof value.semantic.model === "string" && value.semantic.model.trim())
                semantic.model = value.semantic.model.trim();
            semantic.maxChars = positiveInteger(value.semantic.maxChars, semantic.maxChars, "semantic.maxChars", diagnostics, HARD_LIMITS.maxSemanticChars);
        }
        else {
            diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: "semantic must be an object." });
        }
    }
    return {
        failOn,
        ignore: stringArray(value.ignore, "ignore", diagnostics),
        disableRules: stringArray(value.disableRules, "disableRules", diagnostics),
        overrides: parseOverrides(value.overrides, diagnostics),
        maxFileBytes: positiveInteger(value.maxFileBytes, DEFAULT_CONFIG.maxFileBytes, "maxFileBytes", diagnostics, HARD_LIMITS.maxFileBytes),
        maxFiles: positiveInteger(value.maxFiles, DEFAULT_CONFIG.maxFiles, "maxFiles", diagnostics, HARD_LIMITS.maxFiles),
        semantic,
    };
}
export async function loadConfig(root, configPath, useConfig = true) {
    const diagnostics = [];
    if (!useConfig)
        return { config: structuredClone(DEFAULT_CONFIG), diagnostics };
    const resolvedPath = path.resolve(root, configPath ?? ".agent-risk-linter.json");
    try {
        const raw = await readFile(resolvedPath, "utf8");
        if (raw.length > 1_000_000) {
            throw new Error("configuration file exceeds 1 MB");
        }
        const parsed = JSON.parse(raw);
        return { config: parseConfig(parsed, diagnostics), diagnostics, path: resolvedPath };
    }
    catch (error) {
        const code = error.code;
        if (code === "ENOENT" && configPath === undefined) {
            return { config: structuredClone(DEFAULT_CONFIG), diagnostics };
        }
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Could not load configuration ${resolvedPath}: ${message}`);
    }
}
//# sourceMappingURL=config.js.map