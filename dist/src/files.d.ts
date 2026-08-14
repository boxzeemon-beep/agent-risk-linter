import type { FileKind, ScanDiagnostic, SourceFile } from "./types.js";
export interface CollectOptions {
    root: string;
    ignore: string[];
    maxFileBytes: number;
    maxFiles: number;
}
export interface CollectResult {
    files: SourceFile[];
    diagnostics: ScanDiagnostic[];
}
export declare function classifyFile(relativePath: string): FileKind;
export declare function collectFiles(options: CollectOptions): Promise<CollectResult>;
