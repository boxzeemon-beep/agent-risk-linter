import { toSarif } from "./sarif.js";
import { sanitizeTerminalText } from "./redact.js";
import type { Finding, ScanResult, Severity } from "./types.js";

export type OutputFormat = "text" | "json" | "sarif";

interface TextOptions {
  color?: boolean;
}

const COLOR: Record<Severity, string> = {
  critical: "\u001B[1;31m",
  high: "\u001B[31m",
  medium: "\u001B[33m",
  low: "\u001B[36m",
};
const RESET = "\u001B[0m";

function formatBytes(bytes: number): string {
  if (bytes < 1_024) return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1_024).toFixed(1)} KiB`;
  return `${(bytes / 1_048_576).toFixed(1)} MiB`;
}

function severityLabel(finding: Finding, color: boolean): string {
  const label = finding.severity.toUpperCase().padEnd(8);
  return color ? `${COLOR[finding.severity]}${label}${RESET}` : label;
}

export function renderText(result: ScanResult, options: TextOptions = {}): string {
  const color = options.color ?? false;
  const lines = [
    `Agent Risk Linter ${result.tool.version}`,
    `Scanned ${result.filesScanned} files (${formatBytes(result.bytesScanned)}) under ${sanitizeTerminalText(result.root)}`,
    `Findings: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low`,
  ];

  if (result.findings.length === 0) {
    lines.push("", "No findings. This heuristic scan is not a guarantee that the project is safe.");
  } else {
    for (const finding of result.findings) {
      lines.push(
        "",
        `${severityLabel(finding, color)} ${finding.ruleId}  ${sanitizeTerminalText(finding.file)}:${finding.line}:${finding.column}`,
        `  ${finding.title}`,
        `  ${finding.description}`,
      );
      if (finding.excerpt) lines.push(`  > ${finding.excerpt}`);
      lines.push(`  Fix: ${finding.remediation}`);
      if (finding.source === "semantic") lines.push("  Source: opt-in semantic review; verify manually.");
    }
  }

  const warnings = result.diagnostics.filter((diagnostic) => diagnostic.level === "warning");
  if (warnings.length > 0) {
    lines.push("", "Diagnostics:");
    for (const diagnostic of warnings) lines.push(`  [${diagnostic.code}] ${diagnostic.file ? `${sanitizeTerminalText(diagnostic.file)}: ` : ""}${sanitizeTerminalText(diagnostic.message)}`);
  }

  return `${lines.join("\n")}\n`;
}

export function renderResult(result: ScanResult, format: OutputFormat, options: TextOptions = {}): string {
  if (format === "json") return `${JSON.stringify(result, null, 2)}\n`;
  if (format === "sarif") return `${JSON.stringify(toSarif(result), null, 2)}\n`;
  return renderText(result, options);
}
