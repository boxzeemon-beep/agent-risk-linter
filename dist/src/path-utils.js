import path from "node:path";
export function toPosixPath(value) {
    return value.split(path.sep).join("/");
}
export function normalizePattern(value) {
    return value.trim().replaceAll("\\", "/").replace(/^\.\//, "");
}
function escapeRegex(value) {
    return value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}
export function globToRegExp(pattern) {
    let normalized = normalizePattern(pattern);
    if (normalized.endsWith("/")) {
        normalized += "**";
    }
    if (!normalized.includes("/")) {
        normalized = `**/${normalized}`;
    }
    let source = "";
    for (let index = 0; index < normalized.length; index += 1) {
        const character = normalized[index] ?? "";
        const next = normalized[index + 1];
        if (character === "*" && next === "*") {
            const afterGlobstar = normalized[index + 2];
            if (afterGlobstar === "/") {
                source += "(?:.*/)?";
                index += 2;
            }
            else {
                source += ".*";
                index += 1;
            }
            continue;
        }
        if (character === "*") {
            source += "[^/]*";
            continue;
        }
        if (character === "?") {
            source += "[^/]";
            continue;
        }
        source += escapeRegex(character);
    }
    return new RegExp(`^${source}$`, "i");
}
export function matchesAnyGlob(relativePath, patterns) {
    const normalizedPath = normalizePattern(relativePath);
    return patterns.some((pattern) => globToRegExp(pattern).test(normalizedPath));
}
export function isPathInside(parent, candidate) {
    const relative = path.relative(parent, candidate);
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
//# sourceMappingURL=path-utils.js.map