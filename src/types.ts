export const SEVERITIES = ["low", "medium", "high", "critical"] as const;

export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export type FileKind =
  | "instruction"
  | "script"
  | "manifest"
  | "workflow"
  | "config"
  | "document";

export type FindingSource = "static" | "semantic";

export interface SourceFile {
  absolutePath: string;
  relativePath: string;
  kind: FileKind;
  content: string;
  bytes: number;
}

export interface RuleContext {
  file: SourceFile;
}

export interface RuleMatch {
  index: number;
  length: number;
  message?: string;
}

export interface Rule {
  id: string;
  title: string;
  description: string;
  remediation: string;
  severity: Severity;
  category: string;
  appliesTo: readonly FileKind[];
  detect(context: RuleContext): RuleMatch[];
}

export interface Finding {
  ruleId: string;
  title: string;
  description: string;
  remediation: string;
  severity: Severity;
  category: string;
  source: FindingSource;
  file: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  excerpt: string;
  fingerprint: string;
}

export interface ScanDiagnostic {
  level: "info" | "warning";
  code: string;
  message: string;
  file?: string;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface ScanResult {
  schemaVersion: "1.0";
  tool: {
    name: "agent-risk-linter";
    version: string;
  };
  root: string;
  generatedAt: string;
  filesScanned: number;
  bytesScanned: number;
  findings: Finding[];
  diagnostics: ScanDiagnostic[];
  summary: ScanSummary;
}

export interface ConfigOverride {
  files: string[];
  disableRules: string[];
}

export interface LinterConfig {
  failOn: Severity | "none";
  ignore: string[];
  disableRules: string[];
  overrides: ConfigOverride[];
  maxFileBytes: number;
  maxFiles: number;
  semantic: {
    model: string;
    maxChars: number;
  };
}

export interface ScanOptions {
  root: string;
  configPath?: string;
  useConfig?: boolean;
  ignore?: string[];
  disabledRules?: string[];
  maxFileBytes?: number;
  maxFiles?: number;
}

export interface ScanExecution {
  result: ScanResult;
  files: SourceFile[];
  config: LinterConfig;
}

export interface SemanticFindingInput {
  severity: Severity;
  category: string;
  title: string;
  description: string;
  remediation: string;
  file: string;
  line: number;
}

export interface SemanticReviewOptions {
  apiKey: string;
  model: string;
  maxChars: number;
  endpoint?: string;
  timeoutMs?: number;
}
