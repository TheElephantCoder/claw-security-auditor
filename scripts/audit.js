#!/usr/bin/env node
/**
 * OpenClaw Security Auditor — CLI (v4, thin wrapper over lib/).
 * Static analysis only. Never executes skill code.
 *
 * Usage:
 *   node audit.js                         # scan all default skill paths
 *   node audit.js --dir <path>            # scan skills in a specific directory
 *   node audit.js --skill <name>          # scan one skill by name
 *   node audit.js --output json           # machine-readable JSON output
 *   node audit.js --output markdown       # Markdown-formatted report
 *   node audit.js --output csv            # CSV export (one row per skill)
 *   node audit.js --output sarif          # SARIF 2.1.0 (GitHub code scanning)
 *   node audit.js --output html           # standalone HTML report
 *   node audit.js --quiet                 # one line per skill (CI-friendly)
 *   node audit.js --save                  # save report to ~/.openclaw/security-reports/
 *   node audit.js --compare               # diff against last saved report
 *   node audit.js --fix                   # generate patched SKILL.md with risky perms stripped
 *   node audit.js --trust                 # show trust score history for all skills
 *   node audit.js --stats                 # show rule-frequency analytics across all skills
 *   node audit.js --severity high         # only show High risk skills
 *   node audit.js --fail-on high          # exit 1 if any High risk found (CI gate)
 *   node audit.js --exclude name,substr   # skip skills whose name/path matches
 *   node audit.js --config audit.json     # load defaults from a JSON config file
 *   node audit.js --list-rules            # print all detection rules
 *
 * Exit codes: 0 = clean (or threshold not met), 1 = --fail-on threshold met,
 *             2 = usage / runtime error.
 */

"use strict";

const { RULES } = require("../lib/rules");
const {
  DEFAULT_SKILL_PATHS,
  argValue,
  hasFlag,
  discoverSkills,
  loadTrustDB,
  loadWhitelist,
} = require("../lib/utils");
const {
  ENGINE_VERSION,
  analyzeSkill,
  showTrustReport,
} = require("../lib/analyze");
const {
  formatTextReport,
  formatMarkdownReport,
  formatQuietReport,
  formatCSVReport,
  formatSARIFReport,
  formatHTMLReport,
  showStatsReport,
  compareWithLastReport,
  generateFix,
  shouldFail,
  saveReportToDisk,
  listRules,
} = require("../lib/report");
const { loadConfigFile } = require("../lib/config");

// ─── CLI args (+ optional config file) ───────────────────────────────────────

const args = process.argv.slice(2);

if (hasFlag(args, "--help") || hasFlag(args, "-h")) {
  console.log(`claw-security-auditor v${ENGINE_VERSION} — ${RULES.length} checks\n`);
  console.log(`Usage: node scripts/audit.js [options]\n`);
  console.log(`  --dir <path>        scan skills in a specific directory`);
  console.log(`  --skill <name>      scan one skill by name`);
  console.log(`  --output <format>   text|markdown|json|csv|sarif|html|quiet`);
  console.log(`  --quiet             one line per skill (CI-friendly)`);
  console.log(`  --severity <level>  only show high|medium|low skills`);
  console.log(`  --fail-on <level>   exit 1 if findings at/above level (CI gate)`);
  console.log(`  --exclude <csv>     skip skills whose name/path contains a substring`);
  console.log(`  --config <file>     load defaults from a JSON config file`);
  console.log(`  --save              save report to ~/.openclaw/security-reports/`);
  console.log(`  --compare           diff against last saved report`);
  console.log(`  --fix               write SKILL.patched.md with risky perms stripped`);
  console.log(`  --trust             show trust score history`);
  console.log(`  --stats             show rule-frequency analytics`);
  console.log(`  --list-rules        print all detection rules and exit`);
  process.exit(0);
}

const cli = {
  skill: argValue(args, "--skill") || null,
  output: argValue(args, "--output") || null,
  save: hasFlag(args, "--save"),
  compare: hasFlag(args, "--compare"),
  fix: hasFlag(args, "--fix"),
  trust: hasFlag(args, "--trust"),
  stats: hasFlag(args, "--stats"),
  severity: (argValue(args, "--severity") || "").toLowerCase() || null,
  failOn: (argValue(args, "--fail-on") || "").toLowerCase() || null,
  quiet: hasFlag(args, "--quiet"),
  dir: argValue(args, "--dir") || null,
  excludeRaw: argValue(args, "--exclude") || null,
  listRules: hasFlag(args, "--list-rules"),
};

let cfg = {};
const configPath = argValue(args, "--config");
if (configPath) {
  try {
    cfg = loadConfigFile(configPath);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(2);
  }
}

// Merge: explicit CLI flags win over the config file.
const targetSkill =
  cli.skill || cfg.skill || null;
let outputMode =
  cli.output || cfg.output || (cli.quiet || cfg.quiet ? "quiet" : "text");
if (outputMode === "md") outputMode = "markdown";
const saveReport = cli.save || cfg.save || false;
const compareMode = cli.compare;
const fixMode = cli.fix;
const trustMode = cli.trust;
const statsMode = cli.stats;
const severityFilter =
  cli.severity || cfg.severity || null;
const failOn =
  cli.failOn || cfg.failOn || null;
const extraDir = cli.dir || cfg.dir || null;
const excludeList = [
  ...(cfg.exclude || []),
  ...(cli.excludeRaw ? cli.excludeRaw.split(",").map((s) => s.trim()).filter(Boolean) : []),
];

const VALID_OUTPUTS = new Set([
  "text",
  "markdown",
  "json",
  "csv",
  "sarif",
  "html",
  "quiet",
]);

// Skill search paths — extraDir is prepended so it wins over everything.
const path = require("path");
const SKILL_PATHS = extraDir
  ? [path.resolve(extraDir), ...DEFAULT_SKILL_PATHS]
  : DEFAULT_SKILL_PATHS;

// ─── Main ─────────────────────────────────────────────────────────────────────

function main() {
  if (cli.listRules) {
    console.log(listRules());
    return;
  }

  if (!VALID_OUTPUTS.has(outputMode)) {
    console.error(
      `Error: unknown --output "${outputMode}". Use: text|markdown|json|csv|sarif|html|quiet`
    );
    process.exit(2);
  }

  if (severityFilter && !["high", "medium", "low"].includes(severityFilter)) {
    console.error(`Error: --severity must be high, medium, or low.`);
    process.exit(2);
  }

  if (failOn && !["high", "medium", "low"].includes(failOn)) {
    console.error(`Error: --fail-on must be high, medium, or low.`);
    process.exit(2);
  }

  // Trust history display mode
  if (trustMode) {
    showTrustReport();
    return;
  }

  let skills = discoverSkills(extraDir);

  if (skills.length === 0) {
    console.log("No OpenClaw skills found. Searched:");
    SKILL_PATHS.forEach((p) => console.log(`  ${p}`));
    console.log("\nTip: use --dir <path> to scan a specific skills directory.");
    process.exit(0);
  }

  // Exclude filter (config + --exclude)
  if (excludeList.length > 0) {
    skills = skills.filter(
      (s) =>
        !excludeList.some(
          (sub) => s.name.includes(sub) || s.location.includes(sub)
        )
    );
  }

  // Filter to single skill if requested
  if (targetSkill) {
    skills = skills.filter(
      (s) => s.name.toLowerCase() === targetSkill.toLowerCase()
    );
    if (skills.length === 0) {
      console.error(`Skill not found: "${targetSkill}"`);
      console.error(
        "Available skills: " + discoverSkills(extraDir).map((s) => s.name).join(", ")
      );
      process.exit(2);
    }
  }

  if (skills.length === 0) {
    console.log("No skills left to scan after filters.");
    process.exit(0);
  }

  // Analyze all skills
  const results = skills.map((skill) => {
    try {
      return analyzeSkill(skill);
    } catch (err) {
      return {
        name: skill.name,
        location: skill.location,
        riskScore: 50,
        riskLevel: "Medium",
        isWhitelisted: false,
        trustScore: { score: 50, scanCount: 0 },
        frontmatter: {},
        triggeredRules: [],
        behaviors: [`Analysis error: ${err.message}`],
        threats: ["Could not complete analysis — treat as untrusted"],
        simulation: null,
        recommendations: [
          "Manually inspect this skill — automated analysis failed",
        ],
        fileCount: 0,
        unreadableCount: 0,
        scannedAt: new Date().toISOString(),
        engineVersion: ENGINE_VERSION,
      };
    }
  });

  // Compare mode
  if (compareMode) {
    compareWithLastReport(results);
  }

  // Stats mode
  if (statsMode) {
    showStatsReport(results);
    if (!saveReport) return finalize(results);
  }

  // Severity filter
  const filteredResults = severityFilter
    ? results.filter((r) => r.riskLevel.toLowerCase() === severityFilter)
    : results;

  if (severityFilter && filteredResults.length === 0) {
    console.log(`No skills found with severity: ${severityFilter}`);
    return finalize(results);
  }

  // Output
  if (outputMode === "json") {
    const out = JSON.stringify(filteredResults, null, 2);
    console.log(out);
    if (saveReport) saveReportToDisk(out, filteredResults, "json");
    return finalize(results);
  }

  if (outputMode === "csv") {
    const out = formatCSVReport(filteredResults);
    console.log(out);
    if (saveReport) saveReportToDisk(out, filteredResults, "csv");
    return finalize(results);
  }

  if (outputMode === "sarif") {
    const out = formatSARIFReport(filteredResults);
    console.log(out);
    if (saveReport) saveReportToDisk(out, filteredResults, "sarif");
    return finalize(results);
  }

  if (outputMode === "html") {
    const out = formatHTMLReport(filteredResults);
    console.log(out);
    if (saveReport) saveReportToDisk(out, filteredResults, "html");
    return finalize(results);
  }

  if (outputMode === "quiet") {
    console.log(formatQuietReport(filteredResults));
    return finalize(results);
  }

  const report =
    outputMode === "markdown"
      ? formatMarkdownReport(filteredResults)
      : formatTextReport(filteredResults);

  console.log(report);

  if (saveReport) saveReportToDisk(report, filteredResults, outputMode);

  // Fix mode — generate patched SKILL.md files
  if (fixMode) {
    console.log("\nFIX MODE — generating patched SKILL.md files:\n");
    results.forEach((r) => generateFix(r));
  }

  finalize(results);
}

// Apply --fail-on exit code. Whitelisted skills never trip the gate.
function finalize(results) {
  if (shouldFail(results, failOn)) {
    console.error(
      `\nFailing with exit code 1: findings at or above "--fail-on ${failOn}".`
    );
    process.exitCode = 1;
  }
}

// Only run main() when executed directly, not when required as a module
if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(`Fatal error: ${err.message}`);
    process.exit(2);
  }
}

// ─── Public API (used by dashboard.js and external tooling) ───────────────────
// Kept stable across the v3 → v4 modularization: dashboard.js requires
// this file and keeps working without changes.
module.exports = {
  discoverSkills,
  analyzeSkill,
  loadTrustDB,
  loadWhitelist,
  showStatsReport,
  formatCSVReport,
  formatSARIFReport,
  formatHTMLReport,
  SKILL_PATHS,
  DEFAULT_SKILL_PATHS,
  ENGINE_VERSION,
};
