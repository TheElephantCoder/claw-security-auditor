#!/usr/bin/env node
/**
 * Pack a clean, publish-ready ClawHub skill folder (v4).
 *
 *   node scripts/pack.js                      # → dist/security-auditor/
 *   node scripts/pack.js --out <dir>          # → <dir>/
 *   npm run pack
 *
 * Copies only the runtime files. Dev-only content stays out of the bundle:
 * data/sample-skills + data/test-fixtures (intentionally risky demo code
 * that would trip registry security scanners) and scripts/test.js (needs
 * those fixtures to pass). Mirrors .clawhubignore so publishing the repo
 * root directly would produce the same file set.
 *
 * Validates that the SKILL.md frontmatter `name` matches the output folder
 * name (ClawHub requires this for portable Agent Skills).
 */

"use strict";

const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.join(__dirname, "..");
const SKILL_NAME = "security-auditor";

const INCLUDE_FILES = [
  "SKILL.md",
  "README.md",
  "LICENSE",
  "CHANGELOG.md",
  "package.json",
  ".clawhubignore",
  "ui/index.html",
  "data/example-output.md",
];

const INCLUDE_DIRS = ["lib", "scripts"];

// Basenames skipped even inside included dirs (dev-only tooling).
const EXCLUDE_BASENAMES = new Set(["test.js"]);

function argValue(arr, flag) {
  const i = arr.indexOf(flag);
  return i !== -1 ? arr[i + 1] : null;
}

const outDir = path.resolve(
  argValue(process.argv.slice(2), "--out") ||
    path.join(REPO_ROOT, "dist", SKILL_NAME)
);

function copyFile(src, dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
  return fs.statSync(src).size;
}

function copyDir(relDir, destRoot) {
  let bytes = 0;
  let count = 0;
  const absSrc = path.join(REPO_ROOT, relDir);
  const entries = fs.readdirSync(absSrc, { withFileTypes: true });
  for (const entry of entries) {
    if (EXCLUDE_BASENAMES.has(entry.name)) continue;
    const src = path.join(absSrc, entry.name);
    const dest = path.join(destRoot, relDir, entry.name);
    if (entry.isDirectory()) {
      const sub = copyDir(path.join(relDir, entry.name), destRoot);
      bytes += sub.bytes;
      count += sub.count;
    } else if (entry.isFile()) {
      bytes += copyFile(src, dest);
      count++;
    }
  }
  return { bytes, count };
}

// Clean slate (but never delete outside a `security-auditor` folder).
if (path.basename(outDir) !== SKILL_NAME) {
  console.error(`Refusing to pack into "${outDir}": folder must be named "${SKILL_NAME}".`);
  process.exit(2);
}
fs.rmSync(outDir, { recursive: true, force: true });

let bytes = 0;
let count = 0;

for (const rel of INCLUDE_FILES) {
  const src = path.join(REPO_ROOT, rel);
  if (!fs.existsSync(src)) {
    console.error(`Missing expected file: ${rel}`);
    process.exit(2);
  }
  bytes += copyFile(src, path.join(outDir, rel));
  count++;
}

for (const rel of INCLUDE_DIRS) {
  const sub = copyDir(rel, outDir);
  bytes += sub.bytes;
  count += sub.count;
}

// Validate: frontmatter name must match the folder name.
const skillMd = fs.readFileSync(path.join(outDir, "SKILL.md"), "utf8");
const nameMatch = skillMd.match(/^name:\s*(.+?)\s*$/m);
const frontmatterName = nameMatch ? nameMatch[1].replace(/^['"]|['"]$/g, "") : null;
if (frontmatterName !== SKILL_NAME) {
  console.error(
    `SKILL.md frontmatter name is "${frontmatterName}", expected "${SKILL_NAME}".`
  );
  process.exit(2);
}

console.log(`\nPacked ${SKILL_NAME}/ → ${outDir}`);
console.log(`Files: ${count}  Size: ${(bytes / 1024).toFixed(1)} KB`);
console.log(`Frontmatter name ✓  (${frontmatterName})`);
console.log(`\nPublish with:\n  clawhub skill publish ${outDir} \\\n    --slug ${SKILL_NAME} \\\n    --version ${require(path.join(REPO_ROOT, "package.json")).version} \\\n    --categories security,development \\\n    --topics "security-scan,static-analysis,prompt-injection,sarif,skill-safety"\n`);
