import { lstatSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep, win32 } from "node:path";

export type PathBoundaryResult = {
  allowed: boolean;
  target: string;
  root?: string;
  reason?: string;
};

export function canonicalizePath(inputPath: string): string {
  let cursor = resolve(inputPath);
  const missing: string[] = [];

  while (true) {
    try {
      lstatSync(cursor);
      break;
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
      const parent = dirname(cursor);
      if (parent === cursor) throw error;
      missing.unshift(basename(cursor));
      cursor = parent;
    }
  }

  const canonicalAncestor = realpathSync.native(cursor);
  return missing.length ? resolve(canonicalAncestor, ...missing) : canonicalAncestor;
}

export function pathWithinRoot(targetPath: string, allowedRoot: string): PathBoundaryResult {
  if (!isAbsolute(allowedRoot)) {
    return { allowed: false, target: resolve(targetPath), reason: `allowed write root must be absolute: ${allowedRoot}` };
  }

  try {
    const canonicalRoot = canonicalizePath(allowedRoot);
    if (statExists(canonicalRoot) && !statSync(canonicalRoot).isDirectory()) {
      return { allowed: false, target: resolve(targetPath), root: canonicalRoot, reason: `allowed write root is not a directory: ${allowedRoot}` };
    }
    const canonicalTarget = canonicalizePath(targetPath);
    const escaped = !pathInsideCanonicalRoot(canonicalTarget, canonicalRoot);
    return escaped
      ? { allowed: false, target: canonicalTarget, root: canonicalRoot, reason: `write path escapes allowed root: ${allowedRoot}` }
      : { allowed: true, target: canonicalTarget, root: canonicalRoot };
  } catch (error) {
    return {
      allowed: false,
      target: resolve(targetPath),
      reason: `cannot canonicalize write path: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

export function pathInsideCanonicalRoot(target: string, root: string, style: "native" | "win32" = "native"): boolean {
  const pathApi = style === "win32" ? win32 : { relative, isAbsolute, sep };
  const rel = pathApi.relative(root, target);
  return rel !== ".." && !rel.startsWith(`..${pathApi.sep}`) && !pathApi.isAbsolute(rel);
}

export function matchAllowedWritePath(requestedPath: string, allowedRoots: string[], baseDir = process.cwd()): PathBoundaryResult {
  const targetPath = isAbsolute(requestedPath) ? resolve(requestedPath) : resolve(baseDir, requestedPath);
  if (!allowedRoots.length) return { allowed: false, target: targetPath, reason: "no allowed write roots are configured" };

  const failures: string[] = [];
  for (const root of allowedRoots) {
    const result = pathWithinRoot(targetPath, root);
    if (result.allowed) return result;
    if (result.reason) failures.push(result.reason);
  }
  return { allowed: false, target: targetPath, reason: failures[0] || "write path is outside allowed roots" };
}

function isMissingPathError(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && (error as { code?: string }).code === "ENOENT");
}

function statExists(value: string): boolean {
  try {
    statSync(value);
    return true;
  } catch (error) {
    if (isMissingPathError(error)) return false;
    throw error;
  }
}
