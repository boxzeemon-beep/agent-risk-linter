import type { Rule, Severity } from "./types.js";
export declare const RULES: readonly Rule[];
export declare function getRule(ruleId: string): Rule | undefined;
export declare function isSeverity(value: string): value is Severity;
