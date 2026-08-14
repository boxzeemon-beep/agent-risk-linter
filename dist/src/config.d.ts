import { type LinterConfig, type ScanDiagnostic } from "./types.js";
export declare const DEFAULT_CONFIG: Readonly<LinterConfig>;
export declare const HARD_LIMITS: {
    readonly maxFileBytes: 10000000;
    readonly maxFiles: 100000;
    readonly maxSemanticChars: 200000;
};
interface LoadedConfig {
    config: LinterConfig;
    diagnostics: ScanDiagnostic[];
    path?: string;
}
export declare function loadConfig(root: string, configPath?: string, useConfig?: boolean): Promise<LoadedConfig>;
export {};
