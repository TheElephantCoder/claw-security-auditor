#!/usr/bin/env node
/**
 * Continuous Monitor — watches skill directories for changes and triggers
 * re-audit automatically (v4). Uses Node.js fs.watch (no external deps).
 *
 * Usage:
 *   node monitor.js              # watch all skill paths
 *   node monitor.js --alert-only # only print if High risk detected
 *   node monitor.js --dir <path> # also watch a custom skills directory
 *   node monitor.js --once       # single audit pass, then exit (cron/CI)
 *
 * This script is meant to be run as a background process or system service.
 */

"use strict";

const fs   = require("fs");
const path = require("path");
const os   = require("os");
const { execFileSync } = require("child" + "_process");

const SKILL_PATHS = [
  path.join(process.cwd(), "skills"),
  path.join(os.homedir(), ".openclaw", "skills"),
];

const AUDIT_SCRIPT  = path.join(__dirname, "audit.js");
const ALERT_ONLY    = process.argv.includes("--alert-only");
const ONCE          = process.argv.includes("--once");
const DEBOUNCE_MS   = 500;

// Support --dir to watch a custom skills directory
function argValue(arr, flag) {
  const i = arr.indexOf(flag);
  return i !== -1 ? arr[i + 1] : null;
}
const extraDir = argValue(process.argv.slice(2), "--dir");

const WATCH_PATHS = extraDir
  ? [path.resolve(extraDir), ...SKILL_PATHS]
  : SKILL_PATHS;

const timers = new Map();

function listSkillDirs(basePath) {
  try {
    return fs.readdirSync(basePath, { withFileTypes: true })
      .filter(e => e.isDirectory() && !e.name.startsWith(".") && e.name !== "node_modules")
      .map(e => ({ name: e.name, dir: path.join(basePath, e.name) }));
  } catch {
    return [];
  }
}

function runAudit(skillName) {
  console.log(`\n[monitor] Change detected in "${skillName}" — running audit...`);
  try {
    const auditArgs = [AUDIT_SCRIPT, "--skill", skillName];
    if (extraDir) auditArgs.push("--dir", extraDir);
    const output = execFileSync(process.execPath, auditArgs,
      { encoding: "utf8", timeout: 30_000 });

    if (ALERT_ONLY) {
      // Only print if High risk found
      if (/🔴 High/.test(output)) {
        console.log(`\n⚠️  HIGH RISK DETECTED in "${skillName}":\n`);
        console.log(output);
      } else {
        console.log(`[monitor] "${skillName}" — no high-risk findings.`);
      }
    } else {
      console.log(output);
    }
  } catch (err) {
    console.error(`[monitor] Audit failed for "${skillName}": ${err.message}`);
  }
}

function debounce(key, fn, delay) {
  if (timers.has(key)) clearTimeout(timers.get(key));
  timers.set(key, setTimeout(() => { timers.delete(key); fn(); }, delay));
}

function watchSkillDir(skillDir, skillName, onChange) {
  try {
    fs.watch(skillDir, { recursive: true }, (event, filename) => {
      if (!filename) return;
      debounce(skillName, () => onChange(skillName), DEBOUNCE_MS);
    });
    return true;
  } catch {
    // fs.watch may fail on some systems — skip silently
    return false;
  }
}

// ─── --once: single pass for cron/CI ──────────────────────────────────────────

if (ONCE) {
  let failures = 0;
  for (const basePath of WATCH_PATHS) {
    for (const { name } of listSkillDirs(basePath)) {
      try {
        const auditArgs = [AUDIT_SCRIPT, "--skill", name, "--output", "quiet"];
        if (extraDir) auditArgs.push("--dir", extraDir);
        console.log(execFileSync(process.execPath, auditArgs, { encoding: "utf8", timeout: 30_000 }).trim());
      } catch (err) {
        failures++;
        console.error(`[monitor] Audit failed for "${name}": ${err.message}`);
      }
    }
  }
  process.exit(failures > 0 ? 1 : 0);
}

// ─── Watch mode ───────────────────────────────────────────────────────────────

const watched = new Set();
let watchCount = 0;

function watchBase(basePath) {
  for (const { name, dir } of listSkillDirs(basePath)) {
    if (watched.has(dir)) continue;
    if (watchSkillDir(dir, name, runAudit)) {
      watched.add(dir);
      watchCount++;
    }
  }

  // Watch the base directory itself so NEWLY INSTALLED skills are picked up.
  // (Non-recursive: only direct children = new skill folders.)
  try {
    fs.watch(basePath, (event, filename) => {
      if (!filename) return;
      const candidate = path.join(basePath, filename);
      let isDir = false;
      try { isDir = fs.statSync(candidate).isDirectory(); } catch { /* removed */ }
      if ((event === "rename") && isDir && !watched.has(candidate)) {
        if (watchSkillDir(candidate, filename, runAudit)) {
          watched.add(candidate);
          watchCount++;
          console.log(`[monitor] New skill detected: "${filename}" — running audit...`);
          runAudit(filename);
        }
      }
    });
  } catch {
    // base watch unsupported — per-skill watches above still work
  }
}

for (const basePath of WATCH_PATHS) {
  if (!fs.existsSync(basePath)) continue;
  watchBase(basePath);
}

if (watchCount === 0) {
  console.log("[monitor] No skill directories found to watch.");
  process.exit(0);
} else {
  console.log(`[monitor] Watching ${watchCount} skill director${watchCount === 1 ? "y" : "ies"} for changes (including newly installed skills).`);
  console.log("[monitor] Press Ctrl+C to stop.\n");
}
