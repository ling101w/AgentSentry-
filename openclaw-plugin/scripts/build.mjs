import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, extname, join, relative } from "node:path";
import { stripTypeScriptTypes } from "node:module";

const rootDir = process.cwd();
const outDir = join(rootDir, "dist");
const sourceDirs = ["core", "server"];
const sourceFiles = ["config.ts", "index.ts"];

function rewriteRelativeImports(code) {
  return code.replace(
    /((?:import|export)\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?|import\s*\()(["'])(\.{1,2}\/[^"']+)\.ts\2/g,
    (_, prefix, quote, specifier) => `${prefix}${quote}${specifier}.js${quote}`,
  );
}

function transpileTsFile(srcPath, destPath) {
  const source = readFileSync(srcPath, "utf8");
  const transpiled = stripTypeScriptTypes(source, {
    mode: "transform",
    sourceUrl: relative(rootDir, srcPath),
  });
  mkdirSync(dirname(destPath), { recursive: true });
  writeFileSync(destPath, rewriteRelativeImports(transpiled));
}

function walkTsFiles(dirPath) {
  for (const entry of readdirSync(dirPath)) {
    const fullPath = join(dirPath, entry);
    const stats = statSync(fullPath);
    if (stats.isDirectory()) {
      walkTsFiles(fullPath);
      continue;
    }
    if (extname(fullPath) !== ".ts") continue;
    const relPath = relative(rootDir, fullPath);
    transpileTsFile(fullPath, join(outDir, relPath).replace(/\.ts$/, ".js"));
  }
}

function copyDir(srcDir, destDir) {
  if (!existsSync(srcDir)) return;
  mkdirSync(destDir, { recursive: true });
  for (const entry of readdirSync(srcDir)) {
    const srcPath = join(srcDir, entry);
    const destPath = join(destDir, entry);
    const stats = statSync(srcPath);
    if (stats.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      copyFileSync(srcPath, destPath);
    }
  }
}

rmSync(outDir, { recursive: true, force: true });

for (const file of sourceFiles) {
  transpileTsFile(join(rootDir, file), join(outDir, file).replace(/\.ts$/, ".js"));
}

for (const dir of sourceDirs) {
  walkTsFiles(join(rootDir, dir));
}

copyDir(join(rootDir, "public"), join(outDir, "public"));
