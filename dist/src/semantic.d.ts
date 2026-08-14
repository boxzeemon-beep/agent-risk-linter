import type { Finding, ScanExecution, SemanticReviewOptions } from "./types.js";
export interface SemanticPayloadFile {
    path: string;
    kind: string;
    content: string;
    truncated: boolean;
}
export interface SemanticPayload {
    notice: string;
    files: SemanticPayloadFile[];
    staticFindings: Array<Pick<Finding, "ruleId" | "severity" | "category" | "file" | "line" | "title" | "excerpt">>;
}
type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
export declare function prepareSemanticPayload(execution: ScanExecution, maxChars: number): SemanticPayload;
export declare function runSemanticReview(execution: ScanExecution, options: SemanticReviewOptions, fetchImpl?: FetchLike): Promise<Finding[]>;
export {};
