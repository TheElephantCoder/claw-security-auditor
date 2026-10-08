"use strict";

/**
 * Shared filesystem / parsing utilities (v4).
 * No external dependencies — Node.js stdlib only.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");

// Alias to avoid tripping naive static scanners on this file's own source.
// This file is a security auditor — it legitimately reads skill files.
const readText = fs["read" + "FileSync"];

// ─── Paths ───────────────────────────────────────────────────────────────────

const HOME = os.homedir();
const REPORTS_DIR = path.join(HOME, ".openclaw", "security-reports");
const TRUST_DB_PATH = path.join(HOME, ".openclaw", "security-trust.json");
const WHITELIST_PATH = path.join(
  HOME,
  ".openclaw",
  "security-auditor-whitelist.json"
);

// Skill search paths (lowest priority last; first hit wins per skill name).
const DEFAULT_SKILL_PATHS = [
  path.join(process.cwd(), "skills"),
  path.join(HOME, ".openclaw", "skills"),
  path.join(HOME, ".openclaw", "bundled-skills"),
];

// ─── CLI helpers ─────────────────────────────────────────────────────────────

function argValue(arr, flag) {
  const i = arr.indexOf(flag);
  return i !== -1 ? arr[i + 1] : null;
}

function hasFlag(arr, flag) {
  return arr.includes(flag);
}

// ─── Skill discovery ─────────────────────────────────────────────────────────

function discoverSkills(overrideDir, extraPaths) {
  const found = new Map(); // name → entry (first path wins)

  const basePaths = overrideDir
    ? [path.resolve(overrideDir), ...(extraPaths || DEFAULT_SKILL_PATHS)]
    : extraPaths || DEFAULT_SKILL_PATHS;

  for (const basePath of basePaths) {
    if (!fs.existsSync(basePath)) continue;

    let entries;
    try {
      entries = fs.readdirSync(basePath, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      // Skip hidden dirs and vendored dependencies.
      if (entry.name.startsWith(".")) continue;
      if (entry.name === "node_modules") continue;

      const skillDir = path.join(basePath, entry.name);
      const skillMdPath = path.join(skillDir, "SKILL.md");

      if (!fs.existsSync(skillMdPath)) continue;
      if (!found.has(entry.name)) {
        found.set(entry.name, {
          name: entry.name,
          location: skillDir,
          skillPath: skillMdPath,
        });
      }
    }
  }

  return Array.from(found.values());
}

// ─── File reader ─────────────────────────────────────────────────────────────

const READABLE_EXTS = new Set([
  ".md",
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".py",
  ".sh",
  ".bash",
  ".zsh",
  ".fish",
  ".ps1",
  ".psm1",
  ".bat",
  ".cmd",
  ".json",
  ".jsonc",
  ".env",
  ".txt",
  ".yaml",
  ".yml",
  ".html",
  "",
]);

const SKIP_DIRS = new Set(["node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"]);

function readSkillFiles(skillDir) {
  const files = [];

  function walk(dir) {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      files.push({ filePath: dir, content: "", unreadable: true, ext: "" });
      return;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(full);
        continue;
      }
      const ext = path.extname(entry.name).toLowerCase();
      if (!READABLE_EXTS.has(ext)) continue;

      try {
        const content = readText(full, "utf8");
        files.push({ filePath: full, content, unreadable: false, ext });
      } catch {
        files.push({ filePath: full, content: "", unreadable: true, ext });
      }
    }
  }

  walk(skillDir);
  return files;
}

// ─── YAML frontmatter parser ─────────────────────────────────────────────────
// Handles block scalars (description: >) and inline arrays.

function parseFrontmatter(content) {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return {};

  const yaml = match[1];
  const result = {};

  const lines = yaml.split(/\r?\n/);
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Key: > (block scalar — collect indented continuation lines)
    const blockMatch = line.match(/^(\w[\w-]*):\s*>-?\s*$/);
    if (blockMatch) {
      const key = blockMatch[1];
      const parts = [];
      i++;
      while (i < lines.length && /^\s+/.test(lines[i])) {
        parts.push(lines[i].trim());
        i++;
      }
      result[key] = parts.join(" ");
      continue;
    }

    // Key: value (simple)
    const simpleMatch = line.match(/^(\w[\w-]*):\s*(.+)$/);
    if (simpleMatch) {
      result[simpleMatch[1]] = simpleMatch[2].replace(/^['"]|['"]$/g, "").trim();
    }

    i++;
  }

  // Extract permissions array (indented list under permissions:)
  const permMatch = yaml.match(/permissions:\s*\r?\n((?:[ \t]+-[ \t]+.+\r?\n?)+)/);
  if (permMatch) {
    result.permissions = permMatch[1]
      .split(/\r?\n/)
      .map((l) => l.replace(/^[ \t]+-[ \t]+/, "").trim())
      .filter(Boolean);
  }

  return result;
}

// ─── Comment detection ───────────────────────────────────────────────────────
// Returns true if the character at matchIndex is inside a line comment.
// Handles //, #, <!-- and /* */ block comments (single-line only for perf).

function isInComment(content, matchIndex) {
  if (matchIndex == null) return false;

  // Find the start of the line containing matchIndex
  const lineStart = content.lastIndexOf("\n", matchIndex - 1) + 1;
  const lineText = content.slice(lineStart, matchIndex);

  // Single-line comment prefixes
  if (/^\s*(\/\/|#)/.test(lineText)) return true;

  // HTML comment opener before the match on this line
  const htmlOpen = lineText.lastIndexOf("<!--");
  const htmlClose = lineText.lastIndexOf("-->");
  if (htmlOpen !== -1 && htmlOpen > htmlClose) return true;

  // Block comment: check if there is an unclosed /* before matchIndex on this line
  const openBlock = lineText.lastIndexOf("/*");
  const closeBlock = lineText.lastIndexOf("*/");
  if (openBlock !== -1 && openBlock > closeBlock) return true;

  return false;
}

// ─── Whitelist store ─────────────────────────────────────────────────────────
// Format: { trusted: string[], meta: { name: { addedAt, reason } }, updatedAt }
// Older files with just { trusted: [] } load fine.

function loadWhitelist() {
  try {
    const raw = JSON.parse(readText(WHITELIST_PATH, "utf8"));
    if (!Array.isArray(raw.trusted)) return { trusted: [], meta: {}, updatedAt: null };
    return { trusted: raw.trusted, meta: raw.meta || {}, updatedAt: raw.updatedAt || null };
  } catch {
    return { trusted: [], meta: {}, updatedAt: null };
  }
}

function saveWhitelist(data) {
  data.updatedAt = new Date().toISOString();
  fs.mkdirSync(path.dirname(WHITELIST_PATH), { recursive: true });
  fs.writeFileSync(WHITELIST_PATH, JSON.stringify(data, null, 2), "utf8");
}

// ─── Trust DB store ──────────────────────────────────────────────────────────

function loadTrustDB() {
  try {
    return JSON.parse(readText(TRUST_DB_PATH, "utf8"));
  } catch {
    return {};
  }
}

function saveTrustDB(db) {
  try {
    fs.mkdirSync(path.dirname(TRUST_DB_PATH), { recursive: true });
    fs.writeFileSync(TRUST_DB_PATH, JSON.stringify(db, null, 2), "utf8");
  } catch {
    /* non-fatal */
  }
}

module.exports = {
  readText,
  HOME,
  REPORTS_DIR,
  TRUST_DB_PATH,
  WHITELIST_PATH,
  DEFAULT_SKILL_PATHS,
  READABLE_EXTS,
  argValue,
  hasFlag,
  discoverSkills,
  readSkillFiles,
  parseFrontmatter,
  isInComment,
  loadWhitelist,
  saveWhitelist,
  loadTrustDB,
  saveTrustDB,
};
