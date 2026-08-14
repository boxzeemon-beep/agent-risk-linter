import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { isPathInside } from "./path-utils.js";

const NO_FOLLOW = typeof constants.O_NOFOLLOW === "number" ? constants.O_NOFOLLOW : 0;

export async function safeWriteText(filePath: string, content: string): Promise<string> {
  const resolved = path.resolve(filePath);
  try {
    const existing = await lstat(resolved);
    if (existing.isSymbolicLink()) throw new Error(`Refusing to write through a symbolic link: ${resolved}`);
    if (!existing.isFile()) throw new Error(`Output path is not a regular file: ${resolved}`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  const handle = await open(resolved, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | NO_FOLLOW, 0o600);
  try {
    await handle.writeFile(content, "utf8");
  } finally {
    await handle.close();
  }
  return resolved;
}

export async function resolveOutputWithin(baseDirectory: string, outputPath: string): Promise<string> {
  const base = await realpath(path.resolve(baseDirectory));
  const resolved = path.resolve(baseDirectory, outputPath);
  const parent = await realpath(path.dirname(resolved));
  if (!isPathInside(base, parent)) throw new Error(`Output must remain inside the GitHub workspace: ${resolved}`);
  return resolved;
}
