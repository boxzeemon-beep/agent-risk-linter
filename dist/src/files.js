import { lstat, readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { matchesAnyGlob, toPosixPath } from "./path-utils.js";
const DEFAULT_IGNORED_DIRECTORIES = new Set([
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".next",
    ".nuxt",
    ".venv",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
]);
const TEXT_EXTENSIONS = new Set([
    ".bash",
    ".bat",
    ".cjs",
    ".cmd",
    ".conf",
    ".go",
    ".ini",
    ".js",
    ".json",
    ".jsonc",
    ".jsx",
    ".md",
    ".mdx",
    ".mjs",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
    ".zsh",
]);
const SPECIAL_TEXT_NAMES = new Set([
    ".cursorrules",
    ".windsurfrules",
    "dockerfile",
    "gemfile",
    "makefile",
    "procfile",
]);
const SCRIPT_EXTENSIONS = new Set([".bash", ".bat", ".cjs", ".cmd", ".js", ".jsx", ".mjs", ".ps1", ".py", ".rb", ".sh", ".ts", ".tsx", ".zsh"]);
const MAX_TOTAL_BYTES = 50_000_000;
export function classifyFile(relativePath) {
    const normalized = toPosixPath(relativePath);
    const lower = normalized.toLowerCase();
    const base = path.posix.basename(lower);
    const extension = path.posix.extname(lower);
    const isRepoPluginMarketplace = /(?:^|\/)(?:\.agents\/plugins|\.claude-plugin)\/marketplace\.json$/.test(lower);
    if (base === "skill.md" ||
        base === "agents.md" ||
        base === "claude.md" ||
        base === "gemini.md" ||
        base === ".cursorrules" ||
        base === ".windsurfrules" ||
        lower.includes("/.agents/skills/") ||
        lower.startsWith(".agents/skills/") ||
        lower.includes("/.claude/skills/") ||
        lower.startsWith(".claude/skills/") ||
        lower.endsWith(".instructions.md") ||
        lower.endsWith(".prompt.md")) {
        return "instruction";
    }
    if (lower.startsWith(".github/workflows/") || lower.includes("/.github/workflows/") || base === "action.yml" || base === "action.yaml") {
        return "workflow";
    }
    if (base === "package.json" ||
        base === "pyproject.toml" ||
        base === "setup.py" ||
        base.startsWith("requirements") ||
        base === "plugin.json" ||
        base === "manifest.json" ||
        isRepoPluginMarketplace) {
        return "manifest";
    }
    if (base === "hooks.json" || base.includes("mcp") || base === "openai.yaml" || extension === ".toml" || extension === ".ini" || extension === ".conf") {
        return "config";
    }
    if (SCRIPT_EXTENSIONS.has(extension) || SPECIAL_TEXT_NAMES.has(base))
        return "script";
    return "document";
}
function looksBinary(buffer) {
    const sampleLength = Math.min(buffer.length, 8_192);
    for (let index = 0; index < sampleLength; index += 1) {
        if (buffer[index] === 0)
            return true;
    }
    return false;
}
function shouldRead(relativePath) {
    const lower = toPosixPath(relativePath).toLowerCase();
    const base = path.posix.basename(lower);
    return TEXT_EXTENSIONS.has(path.posix.extname(lower)) || SPECIAL_TEXT_NAMES.has(base);
}
function hasUnsafePathControls(relativePath) {
    return /[\u0000-\u001F\u007F\u202A-\u202E\u2066-\u2069]/u.test(relativePath);
}
export async function collectFiles(options) {
    const root = path.resolve(options.root);
    const files = [];
    const diagnostics = [];
    const rootStats = await lstat(root);
    if (rootStats.isSymbolicLink()) {
        throw new Error("Refusing to follow a symbolic-link scan target.");
    }
    if (rootStats.isFile()) {
        const relativePath = path.basename(root);
        if (!shouldRead(relativePath))
            return { files, diagnostics };
        if (rootStats.size > options.maxFileBytes) {
            return {
                files,
                diagnostics: [{ level: "info", code: "FILE_TOO_LARGE", message: `File exceeds ${options.maxFileBytes} bytes.`, file: relativePath }],
            };
        }
        const buffer = await readFile(root);
        if (looksBinary(buffer)) {
            return { files, diagnostics: [{ level: "info", code: "BINARY_SKIPPED", message: "Binary-looking file was skipped.", file: relativePath }] };
        }
        return {
            files: [{ absolutePath: root, relativePath, kind: classifyFile(relativePath), content: buffer.toString("utf8"), bytes: buffer.length }],
            diagnostics,
        };
    }
    const pending = [root];
    let totalBytes = 0;
    while (pending.length > 0) {
        const current = pending.pop();
        if (!current)
            break;
        let entries;
        try {
            entries = await readdir(current, { withFileTypes: true });
        }
        catch (error) {
            diagnostics.push({
                level: "warning",
                code: "DIRECTORY_READ_FAILED",
                message: error instanceof Error ? error.message : String(error),
                file: toPosixPath(path.relative(root, current)),
            });
            continue;
        }
        for (const entry of entries) {
            const absolutePath = path.join(current, entry.name);
            const relativePath = toPosixPath(path.relative(root, absolutePath));
            if (hasUnsafePathControls(relativePath)) {
                diagnostics.push({ level: "warning", code: "UNSAFE_PATH_SKIPPED", message: "Path contains control or bidirectional formatting characters and was skipped.", file: "[sanitized unsafe path]" });
                continue;
            }
            if (entry.isSymbolicLink()) {
                diagnostics.push({ level: "info", code: "SYMLINK_SKIPPED", message: "Symbolic link was not followed.", file: relativePath });
                continue;
            }
            if (entry.isDirectory()) {
                if (DEFAULT_IGNORED_DIRECTORIES.has(entry.name.toLowerCase()) || matchesAnyGlob(`${relativePath}/`, options.ignore))
                    continue;
                pending.push(absolutePath);
                continue;
            }
            if (!entry.isFile() || !shouldRead(relativePath) || matchesAnyGlob(relativePath, options.ignore))
                continue;
            if (files.length >= options.maxFiles) {
                diagnostics.push({ level: "warning", code: "MAX_FILES_REACHED", message: `Stopped after ${options.maxFiles} files.` });
                return { files, diagnostics };
            }
            try {
                const stats = await lstat(absolutePath);
                if (stats.size > options.maxFileBytes) {
                    diagnostics.push({ level: "info", code: "FILE_TOO_LARGE", message: `File exceeds ${options.maxFileBytes} bytes.`, file: relativePath });
                    continue;
                }
                if (totalBytes + stats.size > MAX_TOTAL_BYTES) {
                    diagnostics.push({ level: "warning", code: "MAX_TOTAL_BYTES_REACHED", message: `Stopped before exceeding the hard ${MAX_TOTAL_BYTES}-byte scan budget.` });
                    return { files, diagnostics };
                }
                const buffer = await readFile(absolutePath);
                if (looksBinary(buffer)) {
                    diagnostics.push({ level: "info", code: "BINARY_SKIPPED", message: "Binary-looking file was skipped.", file: relativePath });
                    continue;
                }
                files.push({
                    absolutePath,
                    relativePath,
                    kind: classifyFile(relativePath),
                    content: buffer.toString("utf8"),
                    bytes: buffer.length,
                });
                totalBytes += buffer.length;
            }
            catch (error) {
                diagnostics.push({
                    level: "warning",
                    code: "FILE_READ_FAILED",
                    message: error instanceof Error ? error.message : String(error),
                    file: relativePath,
                });
            }
        }
    }
    files.sort((left, right) => left.relativePath.localeCompare(right.relativePath));
    return { files, diagnostics };
}
//# sourceMappingURL=files.js.map