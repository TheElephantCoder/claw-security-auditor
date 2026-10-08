#!/usr/bin/env node
/**
 * Self-test suite for the Security Auditor engine (v4).
 * Run: node scripts/test.js  (or: npm test)
 *
 * Tests the analysis engine against the bundled sample skills and
 * prompt-injection fixtures without needing a live OpenClaw install.
 */

"use strict";

const fs   = require("fs");
const os   = require("os");
const path = require("path");
const { execFileSync } = require("child" + "_process");

const AUDIT    = path.join(__dirname, "audit.js");
const SAMPLES  = path.join(__dirname, "..", "data", "sample-skills");
const FIXTURES = path.join(__dirname, "..", "data", "test-fixtures");
const NODE     = process.execPath;

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ❌ ${name}`);
    console.log(`     ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || "Assertion failed");
}

function runAudit(extraArgs = [], dir = SAMPLES) {
  const output = execFileSync(NODE, [AUDIT, "--dir", dir, ...extraArgs], {
    encoding: "utf8",
    timeout:  15_000,
  });
  return output;
}

function runAuditJSON(extraArgs = [], dir = SAMPLES) {
  const output = execFileSync(NODE, [AUDIT, "--dir", dir, "--output", "json", ...extraArgs], {
    encoding: "utf8",
    timeout:  15_000,
  });
  return JSON.parse(output);
}

console.log("\nOpenClaw Security Auditor — Test Suite\n" + "═".repeat(45) + "\n");

// Run the scan once upfront — reused by all tests to avoid redundant scans
// and repeated trust DB writes.
let cachedResults;
function getResults(extraArgs = []) {
  if (extraArgs.length === 0) {
    if (!cachedResults) cachedResults = runAuditJSON();
    return cachedResults;
  }
  return runAuditJSON(extraArgs);
}

let cachedFixtures;
function getFixtures() {
  if (!cachedFixtures) cachedFixtures = runAuditJSON([], FIXTURES);
  return cachedFixtures;
}

// ── Discovery tests ───────────────────────────────────────────────────────────
console.log("Discovery");

test("finds all 3 sample skills", () => {
  const results = getResults();
  assert(results.length === 3, `Expected 3 skills, got ${results.length}`);
});

test("skill names are correct", () => {
  const results = getResults();
  const names   = results.map(r => r.name).sort();
  assert(names.includes("file-cleaner"),   "Missing file-cleaner");
  assert(names.includes("data-sync"),      "Missing data-sync");
  assert(names.includes("weather-lookup"), "Missing weather-lookup");
});

test("finds both test fixtures", () => {
  const names = getFixtures().map(r => r.name).sort();
  assert(names.includes("shady-helper"), "Missing shady-helper");
  assert(names.includes("clean-minimal"), "Missing clean-minimal");
});

// ── file-cleaner (High risk) ──────────────────────────────────────────────────
console.log("\nfile-cleaner (expected: High risk)");

test("file-cleaner is High risk", () => {
  const skill = getResults().find(r => r.name === "file-cleaner");
  assert(skill, "file-cleaner not found");
  assert(skill.riskLevel === "High", `Expected High, got ${skill.riskLevel}`);
});

test("file-cleaner score >= 60", () => {
  const skill = getResults().find(r => r.name === "file-cleaner");
  assert(skill.riskScore >= 60, `Expected >=60, got ${skill.riskScore}`);
});

test("file-cleaner triggers H1 (shell execution)", () => {
  const skill   = getResults().find(r => r.name === "file-cleaner");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  assert(ruleIds.includes("H1") || ruleIds.includes("H1b"),
    `H1/H1b not triggered. Rules: ${ruleIds.join(", ")}`);
});

test("file-cleaner H1 evidence is tagged as obfuscated evasion", () => {
  const skill = getResults().find(r => r.name === "file-cleaner");
  const h1    = skill.triggeredRules.find(r => r.id === "H1");
  assert(h1, "H1 not triggered");
  assert(h1.evidence.some(e => /obfuscated/.test(e)),
    `Expected evasion tag in H1 evidence: ${JSON.stringify(h1.evidence)}`);
});

test("file-cleaner triggers H3 (file deletion)", () => {
  const skill   = getResults().find(r => r.name === "file-cleaner");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  assert(ruleIds.includes("H3"), `H3 not triggered. Rules: ${ruleIds.join(", ")}`);
});

test("file-cleaner triggers M1 (network calls)", () => {
  const skill   = getResults().find(r => r.name === "file-cleaner");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  assert(ruleIds.includes("M1"), `M1 not triggered. Rules: ${ruleIds.join(", ")}`);
});

test("file-cleaner has malicious simulation", () => {
  const skill = getResults().find(r => r.name === "file-cleaner");
  assert(Array.isArray(skill.simulation) && skill.simulation.length > 0,
    "No malicious simulation generated");
});

test("file-cleaner has recommendations", () => {
  const skill = getResults().find(r => r.name === "file-cleaner");
  assert(skill.recommendations.length > 0, "No recommendations");
});

// ── data-sync (Medium risk) ───────────────────────────────────────────────────
console.log("\ndata-sync (expected: Medium risk)");

test("data-sync is Medium risk", () => {
  const skill = getResults().find(r => r.name === "data-sync");
  assert(skill, "data-sync not found");
  assert(skill.riskLevel === "Medium", `Expected Medium, got ${skill.riskLevel}`);
});

test("data-sync score 30–59", () => {
  const skill = getResults().find(r => r.name === "data-sync");
  assert(skill.riskScore >= 30 && skill.riskScore < 60,
    `Expected 30-59, got ${skill.riskScore}`);
});

test("data-sync triggers M3 (exfiltration)", () => {
  const skill   = getResults().find(r => r.name === "data-sync");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  assert(ruleIds.includes("M3"), `M3 not triggered. Rules: ${ruleIds.join(", ")}`);
});

test("data-sync triggers M1 (network calls)", () => {
  const skill   = getResults().find(r => r.name === "data-sync");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  assert(ruleIds.includes("M1"), `M1 not triggered. Rules: ${ruleIds.join(", ")}`);
});

// ── weather-lookup (Low risk) ─────────────────────────────────────────────────
console.log("\nweather-lookup (expected: Low risk)");

test("weather-lookup is Low risk", () => {
  const skill = getResults().find(r => r.name === "weather-lookup");
  assert(skill, "weather-lookup not found");
  assert(skill.riskLevel === "Low", `Expected Low, got ${skill.riskLevel}`);
});

test("weather-lookup score < 30", () => {
  const skill = getResults().find(r => r.name === "weather-lookup");
  assert(skill.riskScore < 30, `Expected <30, got ${skill.riskScore}`);
});

test("weather-lookup has no simulation (score < 30)", () => {
  const skill = getResults().find(r => r.name === "weather-lookup");
  assert(skill.simulation === null, "Should have no simulation for low-risk skill");
});

// ── Prompt-injection fixtures (v4 rules) ─────────────────────────────────────
console.log("\nPrompt-injection fixtures (v4)");

test("shady-helper is High risk (H17 forces High)", () => {
  const skill = getFixtures().find(r => r.name === "shady-helper");
  assert(skill, "shady-helper not found");
  assert(skill.riskLevel === "High", `Expected High, got ${skill.riskLevel}`);
});

test("shady-helper triggers H17 (prompt injection)", () => {
  const skill   = getFixtures().find(r => r.name === "shady-helper");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  assert(ruleIds.includes("H17"), `H17 not triggered. Rules: ${ruleIds.join(", ")}`);
});

test("shady-helper triggers H18 (safety bypass)", () => {
  const skill   = getFixtures().find(r => r.name === "shady-helper");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  assert(ruleIds.includes("H18"), `H18 not triggered. Rules: ${ruleIds.join(", ")}`);
});

test("shady-helper triggers M21/M22/M23 (exfil/hidden/solicitation)", () => {
  const skill   = getFixtures().find(r => r.name === "shady-helper");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  for (const id of ["M21", "M22", "M23"]) {
    assert(ruleIds.includes(id), `${id} not triggered. Rules: ${ruleIds.join(", ")}`);
  }
});

test("shady-helper simulation mentions agent hijack", () => {
  const skill = getFixtures().find(r => r.name === "shady-helper");
  assert(Array.isArray(skill.simulation) && skill.simulation.length > 0,
    "No malicious simulation generated");
  assert(skill.simulation.some(s => /hijack|prompt-injection/i.test(s)),
    "Simulation does not cover prompt-injection abuse");
});

test("clean-minimal scores 0 with no rules", () => {
  const skill = getFixtures().find(r => r.name === "clean-minimal");
  assert(skill, "clean-minimal not found");
  assert(skill.riskScore === 0, `Expected 0, got ${skill.riskScore}`);
  assert(skill.triggeredRules.length === 0,
    `Expected no rules, got ${skill.triggeredRules.map(r => r.id).join(", ")}`);
});

// ── Output format tests ───────────────────────────────────────────────────────
console.log("\nOutput formats");

test("text report contains summary header", () => {
  const out = runAudit();
  assert(out.includes("OPENCLAW SECURITY AUDIT REPORT"), "Missing report header");
  assert(out.includes("SUMMARY"), "Missing SUMMARY section");
});

test("text report orders High before Low", () => {
  const out    = runAudit();
  const highIdx = out.indexOf("🔴 High");
  const lowIdx  = out.indexOf("🟢 Low");
  assert(highIdx !== -1 && lowIdx !== -1, "Missing risk level markers");
  assert(highIdx < lowIdx, `High (${highIdx}) should appear before Low (${lowIdx})`);
});

test("markdown report is valid markdown", () => {
  const out = runAudit(["--output", "markdown"]);
  assert(out.startsWith("# OpenClaw Security Audit Report"), "Missing markdown H1");
  assert(out.includes("## Summary"), "Missing Summary section");
  assert(out.includes("| Metric |"), "Missing summary table");
});

test("JSON output is valid and has expected fields", () => {
  const skill = getResults()[0];
  assert("name"            in skill, "Missing name");
  assert("riskScore"       in skill, "Missing riskScore");
  assert("riskLevel"       in skill, "Missing riskLevel");
  assert("triggeredRules"  in skill, "Missing triggeredRules");
  assert("behaviors"       in skill, "Missing behaviors");
  assert("threats"         in skill, "Missing threats");
  assert("recommendations" in skill, "Missing recommendations");
  assert("trustScore"      in skill, "Missing trustScore");
  assert("scannedAt"       in skill, "Missing scannedAt");
  assert("scoreBreakdown"  in skill, "Missing scoreBreakdown");
  assert("engineVersion"   in skill, "Missing engineVersion");
});

test("evidence carries file:line numbers", () => {
  const skill = getResults().find(r => r.name === "file-cleaner");
  const h1    = skill.triggeredRules.find(r => r.id === "H1");
  assert(h1.evidence.some(e => /^[^:]+:\d+:/.test(e)),
    `H1 evidence lacks file:line format: ${JSON.stringify(h1.evidence)}`);
});

test("SARIF output is valid SARIF 2.1.0", () => {
  const out  = runAudit(["--output", "sarif"]);
  const sarif = JSON.parse(out);
  assert(sarif.version === "2.1.0", "Bad SARIF version");
  assert(Array.isArray(sarif.runs) && sarif.runs.length === 1, "Expected 1 run");
  const driver = sarif.runs[0].tool.driver;
  assert(driver.rules.length >= 52, `Expected >=52 rules, got ${driver.rules.length}`);
  assert(sarif.runs[0].results.length > 0, "Expected at least one result");
  const r0 = sarif.runs[0].results[0];
  assert(r0.ruleId && r0.level && r0.message && r0.locations, "Malformed SARIF result");
});

test("HTML output is a standalone document", () => {
  const out = runAudit(["--output", "html"]);
  assert(out.includes("<!DOCTYPE html>"), "Missing doctype");
  assert(out.includes("file-cleaner"), "Missing skill content");
});

test("quiet output is one line per skill", () => {
  const out   = runAudit(["--quiet"]).trim().split("\n");
  assert(out.length === 3, `Expected 3 lines, got ${out.length}`);
  assert(out.some(l => /^file-cleaner: \d+\/100 High$/.test(l)),
    `Unexpected quiet format: ${out.join(" | ")}`);
});

test("--list-rules prints the catalog incl. H17", () => {
  const out = execFileSync(NODE, [AUDIT, "--list-rules"], { encoding: "utf8", timeout: 5_000 });
  assert(out.includes("52 checks"), "Missing rule count header");
  assert(out.includes("H17"), "Missing H17 rule");
  assert(out.includes("M23"), "Missing M23 rule");
});

// ── Single skill scan ─────────────────────────────────────────────────────────
console.log("\nSingle skill scan");

test("--skill flag filters to one skill", () => {
  const results = getResults(["--skill", "file-cleaner"]);
  assert(results.length === 1, `Expected 1 result, got ${results.length}`);
  assert(results[0].name === "file-cleaner", "Wrong skill returned");
});

test("--skill with unknown name exits non-zero", () => {
  let threw = false;
  try {
    execFileSync(NODE, [AUDIT, "--dir", SAMPLES, "--skill", "nonexistent-skill-xyz"], {
      encoding: "utf8", timeout: 5_000,
    });
  } catch {
    threw = true;
  }
  assert(threw, "Should have exited non-zero for unknown skill");
});

// ── Filters: exclude + severity + config ─────────────────────────────────────
console.log("\nFilters");

test("--exclude drops matching skills", () => {
  const results = getResults(["--exclude", "file-cleaner"]);
  assert(results.length === 2, `Expected 2 results, got ${results.length}`);
  assert(!results.some(r => r.name === "file-cleaner"), "file-cleaner was not excluded");
});

test("--severity high keeps only High skills", () => {
  const out = runAudit(["--severity", "high", "--output", "quiet"]).trim().split("\n");
  assert(out.length === 1 && out[0].startsWith("file-cleaner"),
    `Unexpected severity filter output: ${out.join(" | ")}`);
});

test("--config file applies severity filter", () => {
  const cfgPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "audit-")), "audit.json");
  fs.writeFileSync(cfgPath, JSON.stringify({ severity: "high" }), "utf8");
  const out = execFileSync(NODE, [AUDIT, "--dir", SAMPLES, "--config", cfgPath, "--output", "quiet"], {
    encoding: "utf8", timeout: 10_000,
  }).trim().split("\n");
  assert(out.length === 1 && out[0].startsWith("file-cleaner"),
    `Unexpected config filter output: ${out.join(" | ")}`);
});

test("--config with bad JSON exits non-zero", () => {
  const badPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "audit-")), "bad.json");
  fs.writeFileSync(badPath, "{not json", "utf8");
  let threw = false;
  try {
    execFileSync(NODE, [AUDIT, "--dir", SAMPLES, "--config", badPath], {
      encoding: "utf8", timeout: 5_000,
    });
  } catch {
    threw = true;
  }
  assert(threw, "Should have exited non-zero for invalid config");
});

// ── CI gate: --fail-on ────────────────────────────────────────────────────────
console.log("\nCI gate (--fail-on)");

test("--fail-on high exits 1 on risky samples", () => {
  let threw = false;
  try {
    execFileSync(NODE, [AUDIT, "--dir", SAMPLES, "--fail-on", "high", "--output", "quiet"], {
      encoding: "utf8", timeout: 10_000,
    });
  } catch (err) {
    threw = true;
    assert(err.status === 1, `Expected exit 1, got ${err.status}`);
  }
  assert(threw, "Should have exited 1 for high-risk samples");
});

test("--fail-on high exits 0 on a clean single skill", () => {
  execFileSync(NODE, [AUDIT, "--dir", SAMPLES, "--skill", "weather-lookup", "--fail-on", "high"], {
    encoding: "utf8", timeout: 10_000,
  });
});

test("--fail-on medium exits 1 when only Medium present", () => {
  let threw = false;
  try {
    execFileSync(NODE, [AUDIT, "--dir", SAMPLES, "--skill", "data-sync", "--fail-on", "medium", "--output", "quiet"], {
      encoding: "utf8", timeout: 10_000,
    });
  } catch (err) {
    threw = true;
    assert(err.status === 1, `Expected exit 1, got ${err.status}`);
  }
  assert(threw, "Should have exited 1 for medium-risk skill");
});

// ── False positive checks ─────────────────────────────────────────────────────
console.log("\nFalse positive checks");

test("weather-lookup does not trigger H1 (no shell exec)", () => {
  const skill   = getResults().find(r => r.name === "weather-lookup");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  assert(!ruleIds.includes("H1") && !ruleIds.includes("H1b"),
    `H1 falsely triggered on weather-lookup. Rules: ${ruleIds.join(", ")}`);
});

test("weather-lookup does not trigger H3 (no file deletion)", () => {
  const skill   = getResults().find(r => r.name === "weather-lookup");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  assert(!ruleIds.includes("H3"),
    `H3 falsely triggered on weather-lookup. Rules: ${ruleIds.join(", ")}`);
});

test("weather-lookup does not trigger H4 (no obfuscation)", () => {
  const skill   = getResults().find(r => r.name === "weather-lookup");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  assert(!ruleIds.includes("H4"),
    `H4 falsely triggered on weather-lookup. Rules: ${ruleIds.join(", ")}`);
});

test("clean-minimal does not trigger prompt-injection rules", () => {
  const skill   = getFixtures().find(r => r.name === "clean-minimal");
  const ruleIds = skill.triggeredRules.map(r => r.id);
  for (const id of ["H17", "H18", "M21", "M22", "M23"]) {
    assert(!ruleIds.includes(id), `${id} falsely triggered on clean-minimal`);
  }
});

// ── Trust score ───────────────────────────────────────────────────────────────
console.log("\nTrust score");

test("trust score is present and in range 0-100", () => {
  for (const r of getResults()) {
    assert(typeof r.trustScore.score === "number",
      `${r.name}: trustScore.score not a number`);
    assert(r.trustScore.score >= 0 && r.trustScore.score <= 100,
      `${r.name}: trustScore.score out of range: ${r.trustScore.score}`);
  }
});

// ── Summary ───────────────────────────────────────────────────────────────────
console.log("\n" + "═".repeat(45));
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  console.log("\nSome tests failed. See details above.");
  process.exit(1);
} else {
  console.log("\nAll tests passed.");
}
