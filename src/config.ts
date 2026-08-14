import { readFile } from "node:fs/promises";
import path from "node:path";
import { SEVERITIES, type ConfigOverride, type LinterConfig, type ScanDiagnostic, type Severity } from "./types.js";

export const DEFAULT_CONFIG: Readonly<LinterConfig> = {
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
} as const;

interface LoadedConfig {
  config: LinterConfig;
  diagnostics: ScanDiagnostic[];
  path?: string;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringArray(value: unknown, field: string, diagnostics: ScanDiagnostic[]): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: `${field} must be an array of strings.` });
    return [];
  }
  return [...new Set(value as string[])];
}

function positiveInteger(
  value: unknown,
  fallback: number,
  field: string,
  diagnostics: ScanDiagnostic[],
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (value === undefined) return fallback;
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

function parseOverrides(value: unknown, diagnostics: ScanDiagnostic[]): ConfigOverride[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: "overrides must be an array." });
    return [];
  }

  const overrides: ConfigOverride[] = [];
  for (const [index, entry] of value.entries()) {
    if (!isObject(entry)) {
      diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: `overrides[${index}] must be an object.` });
      continue;
    }
    const files = stringArray(entry.files, `overrides[${index}].files`, diagnostics);
    const disableRules = stringArray(entry.disableRules, `overrides[${index}].disableRules`, diagnostics);
    if (files.length > 0 && disableRules.length > 0) overrides.push({ files, disableRules });
  }
  return overrides;
}

function parseConfig(value: unknown, diagnostics: ScanDiagnostic[]): LinterConfig {
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

  let failOn: Severity | "none" = DEFAULT_CONFIG.failOn;
  if (value.failOn !== undefined) {
    if (value.failOn === "none" || (typeof value.failOn === "string" && SEVERITIES.includes(value.failOn as Severity))) {
      failOn = value.failOn as Severity | "none";
    } else {
      diagnostics.push({ level: "warning", code: "CONFIG_INVALID", message: "failOn must be low, medium, high, critical, or none." });
    }
  }

  let semantic = { ...DEFAULT_CONFIG.semantic };
  if (value.semantic !== undefined) {
    if (isObject(value.semantic)) {
      if (typeof value.semantic.model === "string" && value.semantic.model.trim()) semantic.model = value.semantic.model.trim();
      semantic.maxChars = positiveInteger(value.semantic.maxChars, semantic.maxChars, "semantic.maxChars", diagnostics, HARD_LIMITS.maxSemanticChars);
    } else {
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

export async function loadConfig(root: string, configPath?: string, useConfig = true): Promise<LoadedConfig> {
  const diagnostics: ScanDiagnostic[] = [];
  if (!useConfig) return { config: structuredClone(DEFAULT_CONFIG), diagnostics };

  const resolvedPath = path.resolve(root, configPath ?? ".agent-risk-linter.json");
  try {
    const raw = await readFile(resolvedPath, "utf8");
    if (raw.length > 1_000_000) {
      throw new Error("configuration file exceeds 1 MB");
    }
    const parsed: unknown = JSON.parse(raw);
    return { config: parseConfig(parsed, diagnostics), diagnostics, path: resolvedPath };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" && configPath === undefined) {
      return { config: structuredClone(DEFAULT_CONFIG), diagnostics };
    }
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not load configuration ${resolvedPath}: ${message}`);
  }
}
