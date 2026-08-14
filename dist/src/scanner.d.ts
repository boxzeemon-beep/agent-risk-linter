import { type Finding, type ScanExecution, type ScanOptions } from "./types.js";
export declare function scanProject(options: ScanOptions): Promise<ScanExecution>;
export declare function addFindings(execution: ScanExecution, additional: Finding[]): ScanExecution;
