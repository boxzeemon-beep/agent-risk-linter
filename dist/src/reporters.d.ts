import type { ScanResult } from "./types.js";
export type OutputFormat = "text" | "json" | "sarif";
interface TextOptions {
    color?: boolean;
}
export declare function renderText(result: ScanResult, options?: TextOptions): string;
export declare function renderResult(result: ScanResult, format: OutputFormat, options?: TextOptions): string;
export {};
