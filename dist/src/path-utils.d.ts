export declare function toPosixPath(value: string): string;
export declare function normalizePattern(value: string): string;
export declare function globToRegExp(pattern: string): RegExp;
export declare function matchesAnyGlob(relativePath: string, patterns: readonly string[]): boolean;
export declare function isPathInside(parent: string, candidate: string): boolean;
