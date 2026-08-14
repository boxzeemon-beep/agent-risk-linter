#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderResult, type OutputFormat } from "./reporters.js";
import { HARD_LIMITS } from "./config.js";
import { getRule, isSeverity, RULES } from "./rules.js";
import { addFindings, scanProject } from "./scanner.js";
import { safeWriteText } from "./safe-write.js";
import { prepareSemanticPayload, runSemanticReview } from "./semantic.js";
import { SEVERITY_RANK, type Severity } from "./types.js";
import { VERSION } from "./version.js";

const HELP = `Agent Risk Linter ${VERSION}

Usage:
  agent-risk-linter scan [path] [options]
  agent-risk-linter rules [rule-id] [--json]

Scan options:
  --format <text|json|sarif>   Output format (default: text)
  -o, --output <file>          Write the report to a file
  --fail-on <severity|none>    Exit 1 at or above the threshold
  --config <file>              Use a specific JSON configuration file
  --no-config                  Do not load .agent-risk-linter.json
  --ignore <glob>              Add an ignored path glob (repeatable)
  --disable-rule <id>          Disable a rule (repeatable)
  --max-file-bytes <number>    Maximum bytes read from one file
  --max-files <number>         Maximum number of files scanned
  --semantic                   Opt in to redacted OpenAI semantic review
  --model <name>               Model for semantic review
  --max-semantic-chars <n>     Maximum redacted file characters sent
  --semantic-preview <file>    Write the redacted payload without a network call
  --quiet                      Suppress progress notices on stderr
  --no-color                   Disable ANSI colors
  -h, --help                   Show help
  -v, --version                Show version

Environment for --semantic:
  OPENAI_API_KEY               Required; read only at request time

Exit codes:
  0  Scan completed below the failure threshold
  1  A finding met the failure threshold
  2  Invalid input, unreadable target, or runtime/API error
`;

interface ScanArguments {
  root: string;
  format: OutputFormat;
  output?: string;
  failOn?: Severity | "none";
  configPath?: string;
  useConfig: boolean;
  ignore: string[];
  disabledRules: string[];
  maxFileBytes?: number;
  maxFiles?: number;
  semantic: boolean;
  model?: string;
  maxSemanticChars?: number;
  semanticPreview?: string;
  quiet: boolean;
  color: boolean;
}

function requireValue(args: string[], option: string): string {
  const value = args.shift();
  if (!value || value.startsWith("-")) throw new Error(`${option} requires a value.`);
  return value;
}

function positiveInteger(value: string, option: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${option} requires a positive integer.`);
  return parsed;
}

function parseScanArguments(args: string[]): ScanArguments {
  const parsed: ScanArguments = {
    root: ".",
    format: "text",
    useConfig: true,
    ignore: [],
    disabledRules: [],
    semantic: false,
    quiet: false,
    color: Boolean(process.stdout.isTTY && !process.env.NO_COLOR),
  };
  let rootSet = false;

  while (args.length > 0) {
    const argument = args.shift() ?? "";
    if (argument === "--format") {
      const value = requireValue(args, argument);
      if (value !== "text" && value !== "json" && value !== "sarif") throw new Error(`Unsupported format: ${value}`);
      parsed.format = value;
    } else if (argument === "-o" || argument === "--output") {
      parsed.output = requireValue(args, argument);
    } else if (argument === "--fail-on") {
      const value = requireValue(args, argument);
      if (value !== "none" && !isSeverity(value)) throw new Error(`Unsupported severity: ${value}`);
      parsed.failOn = value;
    } else if (argument === "--config") {
      parsed.configPath = requireValue(args, argument);
    } else if (argument === "--no-config") {
      parsed.useConfig = false;
    } else if (argument === "--ignore") {
      parsed.ignore.push(requireValue(args, argument));
    } else if (argument === "--disable-rule") {
      parsed.disabledRules.push(requireValue(args, argument).toUpperCase());
    } else if (argument === "--max-file-bytes") {
      parsed.maxFileBytes = positiveInteger(requireValue(args, argument), argument);
    } else if (argument === "--max-files") {
      parsed.maxFiles = positiveInteger(requireValue(args, argument), argument);
    } else if (argument === "--semantic") {
      parsed.semantic = true;
    } else if (argument === "--model") {
      parsed.model = requireValue(args, argument);
    } else if (argument === "--max-semantic-chars") {
      parsed.maxSemanticChars = positiveInteger(requireValue(args, argument), argument);
    } else if (argument === "--semantic-preview") {
      parsed.semanticPreview = requireValue(args, argument);
    } else if (argument === "--quiet") {
      parsed.quiet = true;
    } else if (argument === "--no-color") {
      parsed.color = false;
    } else if (argument === "-h" || argument === "--help") {
      process.stdout.write(HELP);
      throw new EarlyExit(0);
    } else if (argument.startsWith("-")) {
      throw new Error(`Unknown option: ${argument}`);
    } else if (!rootSet) {
      parsed.root = argument;
      rootSet = true;
    } else {
      throw new Error(`Unexpected argument: ${argument}`);
    }
  }
  return parsed;
}

class EarlyExit extends Error {
  constructor(public readonly code: number) {
    super("early exit");
  }
}

function thresholdReached(failOn: Severity | "none", findings: { severity: Severity }[]): boolean {
  if (failOn === "none") return false;
  return findings.some((finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[failOn]);
}

async function runRules(args: string[]): Promise<number> {
  const json = args.includes("--json");
  const ruleId = args.find((argument) => !argument.startsWith("-"));
  if (args.some((argument) => argument.startsWith("-") && argument !== "--json")) throw new Error("rules supports only --json.");
  if (ruleId) {
    const rule = getRule(ruleId);
    if (!rule) throw new Error(`Unknown rule: ${ruleId}`);
    const output = {
      id: rule.id,
      title: rule.title,
      severity: rule.severity,
      category: rule.category,
      description: rule.description,
      remediation: rule.remediation,
      appliesTo: rule.appliesTo,
    };
    process.stdout.write(json ? `${JSON.stringify(output, null, 2)}\n` : `${rule.id} [${rule.severity}] ${rule.title}\n${rule.description}\nFix: ${rule.remediation}\n`);
    return 0;
  }
  const output = RULES.map((rule) => ({ id: rule.id, severity: rule.severity, category: rule.category, title: rule.title }));
  process.stdout.write(json ? `${JSON.stringify(output, null, 2)}\n` : `${output.map((rule) => `${rule.id.padEnd(8)} ${rule.severity.padEnd(8)} ${rule.title}`).join("\n")}\n`);
  return 0;
}

async function runScan(args: string[]): Promise<number> {
  const parsed = parseScanArguments(args);
  let execution = await scanProject({
    root: parsed.root,
    configPath: parsed.configPath,
    useConfig: parsed.useConfig,
    ignore: parsed.ignore,
    disabledRules: parsed.disabledRules,
    maxFileBytes: parsed.maxFileBytes,
    maxFiles: parsed.maxFiles,
  });

  const maxSemanticChars = Math.min(parsed.maxSemanticChars ?? execution.config.semantic.maxChars, HARD_LIMITS.maxSemanticChars);
  if (parsed.semanticPreview) {
    const preview = `${JSON.stringify(prepareSemanticPayload(execution, maxSemanticChars), null, 2)}\n`;
    await safeWriteText(path.resolve(parsed.semanticPreview), preview);
    if (!parsed.quiet) process.stderr.write(`Wrote redacted semantic payload preview to ${parsed.semanticPreview}. No network request was made.\n`);
  }

  if (parsed.semantic) {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) throw new Error("--semantic requires OPENAI_API_KEY. The key is read from the environment and is never written to output.");
    const model = parsed.model ?? execution.config.semantic.model;
    if (!parsed.quiet) process.stderr.write(`Opt-in semantic review: sending at most ${maxSemanticChars} redacted characters to OpenAI using ${model}.\n`);
    const semanticFindings = await runSemanticReview(execution, { apiKey, model, maxChars: maxSemanticChars });
    execution = addFindings(execution, semanticFindings);
  }

  const rendered = renderResult(execution.result, parsed.format, { color: parsed.format === "text" && parsed.color && !parsed.output });
  if (parsed.output) {
    await safeWriteText(path.resolve(parsed.output), rendered);
    if (!parsed.quiet) process.stderr.write(`Wrote ${parsed.format} report to ${parsed.output}.\n`);
  } else {
    process.stdout.write(rendered);
  }

  const failOn = parsed.failOn ?? execution.config.failOn;
  return thresholdReached(failOn, execution.result.findings) ? 1 : 0;
}

export async function runCli(argv = process.argv.slice(2)): Promise<number> {
  if (argv.includes("-v") || argv.includes("--version")) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (argv.length === 0) return runScan([]);
  const args = [...argv];
  const command = args[0] === "scan" || args[0] === "rules" ? args.shift() : "scan";
  return command === "rules" ? runRules(args) : runScan(args);
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath && fileURLToPath(import.meta.url) === invokedPath) {
  runCli()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      if (error instanceof EarlyExit) {
        process.exitCode = error.code;
        return;
      }
      process.stderr.write(`agent-risk-linter: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 2;
    });
}
