import path from "node:path";

export function toPosixPath(value: string): string {
  return value.split(path.sep).join("/");
}

export function normalizePattern(value: string): string {
  return value.trim().replaceAll("\\", "/").replace(/^\.\//, "");
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}

export function globToRegExp(pattern: string): RegExp {
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
      } else {
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

export function matchesAnyGlob(relativePath: string, patterns: readonly string[]): boolean {
  const normalizedPath = normalizePattern(relativePath);
  return patterns.some((pattern) => globToRegExp(pattern).test(normalizedPath));
}

export function isPathInside(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
