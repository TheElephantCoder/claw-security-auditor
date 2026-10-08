"use strict";

/**
 * Report formatters + history helpers (v4).
 * Outputs: text, markdown, csv, sarif (GitHub code scanning), html, quiet.
 */

const fs = require("fs");
const path = require("path");

const { RULES } = require("./rules");
const { REPORTS_DIR, readText } = require("./utils");

let PKG_VERSION = "4.0.0";
try {
  PKG_VERSION = require("../package.json").version || PKG_VERSION;
} catch {
  /* keep default */
}

function riskEmoji(level) {
  return level === "High" ? "🔴" : level === "Medium" ? "🟡" : "🟢";
}

function sarifLevel(level) {
  return level === "High" ? "error" : level === "Medium" ? "warning" : "note";
}

function sarifSeverity(level) {
  return level === "High" ? "9.0" : level === "Medium" ? "5.0" : "2.0";
}

// ─── Text report ─────────────────────────────────────────────────────────────

function formatTextReport(results) {
  const timestamp = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  const high = results.filter((r) => r.riskLevel === "High");
  const medium = results.filter((r) => r.riskLevel === "Medium");
  const low = results.filter((r) => r.riskLevel === "Low");

  let out = "";
  out += "╔══════════════════════════════════════════════════════════════╗\n";
  out += "║           OPENCLAW SECURITY AUDIT REPORT                     ║\n";
  out += `║           Generated: ${timestamp.padEnd(38)}║\n`;
  out += "╚══════════════════════════════════════════════════════════════╝\n\n";

  out += "SUMMARY\n";
  out += "───────\n";
  out += `Total skills scanned : ${results.length}\n`;
  out += `Low risk             : ${low.length}\n`;
  out += `Medium risk          : ${medium.length}\n`;
  out += `High risk            : ${high.length}\n`;
  out += `Immediate threats    : ${
    high.length ? high.map((r) => r.name).join(", ") : "None"
  }\n\n`;
  out += "━".repeat(64) + "\n\n";

  const sorted = [...high, ...medium, ...low];

  for (const r of sorted) {
    if (r.isWhitelisted) {
      out += `Skill Name    : ${r.name}  ✅ WHITELISTED (suppressed)\n`;
      out += "─".repeat(64) + "\n\n";
      continue;
    }

    out += `Skill Name    : ${r.name}\n`;
    out += `Location      : ${r.location}\n`;
    out += `Risk Score    : ${r.riskScore} / 100\n`;
    out += `Risk Level    : ${riskEmoji(r.riskLevel)} ${r.riskLevel}\n`;
    out += `Trust Score   : ${r.trustScore.score}/100 (${r.trustScore.scanCount} scan${
      r.trustScore.scanCount !== 1 ? "s" : ""
    })\n\n`;

    out += "Detected Behaviors:\n";
    r.behaviors.forEach((b) => {
      out += `  • ${b}\n`;
    });
    out += "\n";

    if (r.triggeredRules.length > 0) {
      out += "Triggered Rules:\n";
      r.triggeredRules.forEach((rule) => {
        const ev = Array.isArray(rule.evidence)
          ? rule.evidence.join("; ")
          : rule.evidence;
        out += `  • [${rule.id}] ${rule.label} (+${rule.score}pts) — ${ev}\n`;
      });
      out += "\n";
    }

    out += "Potential Threats:\n";
    r.threats.forEach((t) => {
      out += `  • ${t}\n`;
    });
    out += "\n";

    if (r.simulation) {
      out += "Malicious Simulation:\n";
      r.simulation.forEach((s) => {
        out += wrapText(`  ⚠ ${s}`, 80) + "\n";
      });
      out += "\n";
    }

    out += "Recommended Actions:\n";
    r.recommendations.forEach((rec) => {
      out += `  → ${rec}\n`;
    });
    out += "\n";
    out += "─".repeat(64) + "\n\n";
  }

  const candidates = results.filter(
    (r) => r.riskScore === 0 && r.triggeredRules.length === 0
  );
  out += "WHITELIST CANDIDATES\n────────────────────\n";
  if (candidates.length > 0) {
    candidates.forEach((w) => {
      out += `  • ${w.name} — safe to whitelist\n`;
    });
  } else {
    out += "  None — all skills have at least one finding.\n";
  }
  out += "\n";

  out += "SECURITY HISTORY NOTE\n─────────────────────\n";
  out += `Save this report to ~/.openclaw/security-reports/${new Date()
    .toISOString()
    .slice(0, 10)}.md\n`;
  out += "to maintain an audit trail. Re-run after installing new skills.\n";

  return out;
}

// ─── Markdown report ─────────────────────────────────────────────────────────

function formatMarkdownReport(results) {
  const timestamp = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
  const high = results.filter((r) => r.riskLevel === "High");
  const medium = results.filter((r) => r.riskLevel === "Medium");
  const low = results.filter((r) => r.riskLevel === "Low");

  let md = `# OpenClaw Security Audit Report\n\n`;
  md += `**Generated:** ${timestamp}\n\n`;
  md += `## Summary\n\n`;
  md += `| Metric | Count |\n|--------|-------|\n`;
  md += `| Total scanned | ${results.length} |\n`;
  md += `| 🟢 Low risk | ${low.length} |\n`;
  md += `| 🟡 Medium risk | ${medium.length} |\n`;
  md += `| 🔴 High risk | ${high.length} |\n\n`;

  if (high.length > 0) {
    md += `> **Immediate threats:** ${high
      .map((r) => `\`${r.name}\``)
      .join(", ")}\n\n`;
  }

  md += `---\n\n`;

  const sorted = [...high, ...medium, ...low];
  for (const r of sorted) {
    if (r.isWhitelisted) {
      md += `## ✅ ${r.name} (Whitelisted)\n\n`;
      continue;
    }

    md += `## ${riskEmoji(r.riskLevel)} ${r.name}\n\n`;
    md += `- **Risk Score:** ${r.riskScore}/100\n`;
    md += `- **Risk Level:** ${r.riskLevel}\n`;
    md += `- **Trust Score:** ${r.trustScore.score}/100\n`;
    md += `- **Location:** \`${r.location}\`\n\n`;

    md += `### Detected Behaviors\n\n`;
    r.behaviors.forEach((b) => {
      md += `- ${b}\n`;
    });
    md += "\n";

    if (r.triggeredRules.length > 0) {
      md += `### Triggered Rules\n\n`;
      md += `| Rule | Label | Score | Evidence |\n|------|-------|-------|----------|\n`;
      r.triggeredRules.forEach((rule) => {
        const ev = Array.isArray(rule.evidence)
          ? rule.evidence.join("; ")
          : rule.evidence;
        md += `| \`${rule.id}\` | ${rule.label} | +${rule.score} | ${ev.replace(
          /\|/g,
          "\\|"
        )} |\n`;
      });
      md += "\n";
    }

    md += `### Potential Threats\n\n`;
    r.threats.forEach((t) => {
      md += `- ${t}\n`;
    });
    md += "\n";

    if (r.simulation) {
      md += `### Malicious Simulation\n\n`;
      r.simulation.forEach((s) => {
        md += `> ⚠ ${s}\n\n`;
      });
    }

    md += `### Recommended Actions\n\n`;
    r.recommendations.forEach((rec) => {
      md += `- ${rec}\n`;
    });
    md += "\n---\n\n";
  }

  return md;
}

// ─── Quiet report (CI-friendly one-liner per skill) ───────────────────────────

function formatQuietReport(results) {
  return results
    .map((r) => `${r.name}: ${r.riskScore}/100 ${r.riskLevel}`)
    .join("\n");
}

// ─── CSV report ──────────────────────────────────────────────────────────────

function formatCSVReport(results) {
  const headers = [
    "name",
    "riskScore",
    "riskLevel",
    "trustScore",
    "fileCount",
    "triggeredRuleIds",
    "scannedAt",
    "location",
  ];
  const escape = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const rows = results.map((r) =>
    [
      escape(r.name),
      r.riskScore,
      escape(r.riskLevel),
      r.trustScore.score,
      r.fileCount,
      escape(r.triggeredRules.map((x) => x.id).join("|")),
      escape(r.scannedAt),
      escape(r.location),
    ].join(",")
  );
  return [headers.join(","), ...rows].join("\n");
}

// ─── SARIF report (GitHub code scanning) ─────────────────────────────────────
// Minimal valid SARIF v2.1.0: upload with `gh code-scanning upload-sarif`
// or the github/codeql-action/upload-sarif action.

function sarifLocationFor(skill, rule) {
  const first = Array.isArray(rule.evidence) ? rule.evidence[0] : null;
  const m = typeof first === "string" ? first.match(/^([^:]+):(\d+):/) : null;
  const file = m ? m[1] : "SKILL.md";
  const line = m ? parseInt(m[2], 10) : 1;
  return {
    physicalLocation: {
      artifactLocation: { uri: `${skill.name}/${file}` },
      region: { startLine: Number.isFinite(line) && line > 0 ? line : 1 },
    },
  };
}

function formatSARIFReport(results) {
  const sarifRules = RULES.map((r) => ({
    id: r.id,
    name: r.label,
    shortDescription: { text: `[${r.id}] ${r.label}` },
    fullDescription: { text: `${r.level} risk rule (+${r.score} pts): ${r.label}` },
    properties: {
      "security-severity": sarifSeverity(r.level),
      tags: ["security", `severity/${r.level.toLowerCase()}`],
    },
  }));

  const sarifResults = [];
  for (const skill of results) {
    for (const rule of skill.triggeredRules) {
      if (rule.id === "UNREADABLE") continue; // engine-internal, not a rule
      sarifResults.push({
        ruleId: rule.id,
        level: sarifLevel(rule.level),
        message: {
          text: `[${skill.name}] ${rule.label} (+${rule.score} pts): ${
            Array.isArray(rule.evidence) ? rule.evidence.join("; ") : ""
          }`.slice(0, 1000),
        },
        locations: [sarifLocationFor(skill, rule)],
      });
    }
  }

  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "claw-security-auditor",
              version: PKG_VERSION,
              informationUri:
                "https://github.com/TheElephantCoder/claw-security-auditor",
              rules: sarifRules,
            },
          },
          results: sarifResults,
        },
      ],
    },
    null,
    2
  );
}

// ─── HTML report (standalone, no build step) ─────────────────────────────────

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatHTMLReport(results) {
  const high = results.filter((r) => r.riskLevel === "High").length;
  const medium = results.filter((r) => r.riskLevel === "Medium").length;
  const low = results.filter((r) => r.riskLevel === "Low").length;
  const ts = escapeHtml(new Date().toISOString());

  const cards = results
    .map((r) => {
      const cls =
        r.riskLevel === "High"
          ? "high"
          : r.riskLevel === "Medium"
            ? "med"
            : "low";
      const rules = (r.triggeredRules || [])
        .map(
          (rule) =>
            `<li><code>[${escapeHtml(rule.id)}]</code> ${escapeHtml(
              rule.label
            )} <span class="pts">+${rule.score}</span><br><small>${escapeHtml(
              Array.isArray(rule.evidence) ? rule.evidence.join("; ") : ""
            )}</small></li>`
        )
        .join("");
      const recs = (r.recommendations || [])
        .map((x) => `<li>${escapeHtml(x)}</li>`)
        .join("");
      return `<section class="card ${cls}">
<h2>${riskEmoji(r.riskLevel)} ${escapeHtml(r.name)} <span class="score">${r.riskScore}/100 · ${escapeHtml(r.riskLevel)}</span></h2>
<p class="loc">${escapeHtml(r.location)}</p>
<h3>Triggered rules</h3><ul>${rules || "<li>None</li>"}</ul>
<h3>Recommended actions</h3><ul>${recs}</ul>
</section>`;
    })
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenClaw Security Audit Report</title>
<style>
body{font-family:-apple-system,"Segoe UI",sans-serif;background:#0d1117;color:#e6edf3;max-width:960px;margin:0 auto;padding:24px;font-size:14px;line-height:1.6}
.summary{display:flex;gap:12px;margin:16px 0 24px;flex-wrap:wrap}
.stat{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center}
.stat b{font-size:28px;display:block}
.high h2{color:#f85149}.med h2{color:#d29922}.low h2{color:#3fb950}
.card{background:#161b22;border:1px solid #30363d;border-left-width:3px;border-radius:8px;padding:16px 20px;margin-bottom:12px}
.card.high{border-left-color:#f85149}.card.med{border-left-color:#d29922}.card.low{border-left-color:#3fb950}
.score{font-size:13px;color:#8b949e}.loc{font-size:12px;color:#8b949e;word-break:break-all}
code{background:rgba(255,255,255,.08);padding:1px 6px;border-radius:4px;font-size:12px}
.pts{color:#8b949e;font-size:12px}small{color:#8b949e;word-break:break-all}
</style></head><body>
<h1>🛡️ OpenClaw Security Audit Report</h1>
<p>Generated: ${ts} · engine v${escapeHtml(PKG_VERSION)}</p>
<div class="summary">
<div class="stat"><b>${results.length}</b>scanned</div>
<div class="stat"><b style="color:#f85149">${high}</b>high</div>
<div class="stat"><b style="color:#d29922">${medium}</b>medium</div>
<div class="stat"><b style="color:#3fb950">${low}</b>low</div>
</div>
${cards}
</body></html>`;
}

function wrapText(text, width) {
  const words = text.split(" ");
  const lines = [];
  const indent = "    ";
  let current = "";

  for (const word of words) {
    const candidate = current ? current + " " + word : word;
    if (candidate.length > width && current.length > 0) {
      lines.push(current);
      current = indent + word;
    } else {
      current = candidate;
    }
  }
  if (current) lines.push(current);
  return lines.join("\n");
}

// ─── Stats mode ───────────────────────────────────────────────────────────────
// Shows rule-frequency analytics: which rules fire most often across all skills.

function showStatsReport(results) {
  const ruleFreq = {};
  const ruleLabel = {};
  let totalHigh = 0,
    totalMed = 0,
    totalLow = 0;

  for (const r of results) {
    if (r.riskLevel === "High") totalHigh++;
    if (r.riskLevel === "Medium") totalMed++;
    if (r.riskLevel === "Low") totalLow++;

    for (const rule of r.triggeredRules) {
      ruleFreq[rule.id] = (ruleFreq[rule.id] || 0) + 1;
      ruleLabel[rule.id] = rule.label;
    }
  }

  const sorted = Object.entries(ruleFreq).sort((a, b) => b[1] - a[1]);
  const maxCount = sorted[0]?.[1] || 1;

  console.log("\nSECURITY AUDITOR — RULE FREQUENCY STATS");
  console.log("─".repeat(60));
  console.log(
    `Skills scanned : ${results.length}  (🔴 ${totalHigh} High  🟡 ${totalMed} Medium  🟢 ${totalLow} Low)\n`
  );
  console.log("Most-triggered rules:\n");

  for (const [id, count] of sorted) {
    const bar = "█".repeat(Math.round((count / maxCount) * 20));
    const pct = Math.round((count / results.length) * 100);
    const tier = id[0];
    const emoji = tier === "H" ? "🔴" : tier === "M" ? "🟡" : "🟢";
    console.log(
      `  ${emoji} [${id.padEnd(5)}] ${bar.padEnd(20)} ${count}/${
        results.length
      } (${pct}%)  ${ruleLabel[id] || ""}`
    );
  }

  const avgScore = results.length
    ? Math.round(results.reduce((s, r) => s + r.riskScore, 0) / results.length)
    : 0;
  console.log(`\nAverage risk score : ${avgScore}/100`);
  console.log(
    `Rules with 0 hits  : ${
      RULES.filter((r) => !ruleFreq[r.id])
        .map((r) => r.id)
        .join(", ") || "none"
    }\n`
  );
}

// ─── --fix mode: generate patched SKILL.md ────────────────────────────────────
// Strips dangerous permissions from metadata and writes a .patched.md file.

function generateFix(result) {
  const skillMdPath = result.location + "/SKILL.md";
  const patchedPath = result.location + "/SKILL.patched.md";
  const dangerousPerms = new Set([
    "exec:shell",
    "write:filesystem",
    "read:secrets",
    "network:unrestricted",
    "admin",
  ]);

  let content;
  try {
    content = readText(skillMdPath, "utf8");
  } catch {
    console.error(`  Cannot read ${skillMdPath}`);
    return;
  }

  const claimedPerms = result.frontmatter.permissions || [];
  const toRemove = claimedPerms.filter((p) => dangerousPerms.has(p));

  if (toRemove.length === 0) {
    console.log(`  ${result.name}: no dangerous permissions to strip.`);
    return;
  }

  // Remove each dangerous permission line from the frontmatter
  let patched = content;
  for (const perm of toRemove) {
    // Match "    - exec:shell" style lines
    patched = patched.replace(
      new RegExp(
        `^[ \\t]+-[ \\t]+${perm.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\r?\\n`,
        "m"
      ),
      ""
    );
  }

  // Add a comment noting the patch
  patched = patched.replace(
    /^---\r?\n/,
    `---\n# PATCHED by security-auditor on ${new Date()
      .toISOString()
      .slice(0, 10)}: removed [${toRemove.join(", ")}]\n`
  );

  try {
    fs.writeFileSync(patchedPath, patched, "utf8");
    console.log(`  ${result.name}: patched → ${patchedPath}`);
    console.log(`    Removed permissions: ${toRemove.join(", ")}`);
  } catch (err) {
    console.error(`  ${result.name}: could not write patch — ${err.message}`);
  }
}

// ─── Compare mode: diff against last saved report ─────────────────────────────

function compareWithLastReport(results) {
  if (!fs.existsSync(REPORTS_DIR)) {
    console.log("No previous reports found. Run with --save first.");
    return;
  }

  const reportFiles = fs
    .readdirSync(REPORTS_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();

  if (reportFiles.length === 0) {
    console.log(
      "No previous JSON reports found. Run with --save --output json first."
    );
    return;
  }

  const lastFile = path.join(REPORTS_DIR, reportFiles[reportFiles.length - 1]);
  let lastResults;
  try {
    lastResults = JSON.parse(readText(lastFile, "utf8"));
  } catch {
    console.log(`Could not parse last report: ${lastFile}`);
    return;
  }

  const lastMap = new Map(lastResults.map((r) => [r.name, r]));
  const currMap = new Map(results.map((r) => [r.name, r]));

  console.log(
    "\nCHANGE REPORT (vs " + path.basename(lastFile) + ")\n" + "─".repeat(50)
  );

  let changes = 0;

  // New skills
  for (const [name, curr] of currMap) {
    if (!lastMap.has(name)) {
      console.log(
        `  + NEW    ${name} — ${riskEmoji(curr.riskLevel)} ${curr.riskLevel} (${curr.riskScore}/100)`
      );
      changes++;
    }
  }

  // Removed skills
  for (const [name] of lastMap) {
    if (!currMap.has(name)) {
      console.log(`  - REMOVED ${name}`);
      changes++;
    }
  }

  // Changed risk scores
  for (const [name, curr] of currMap) {
    const prev = lastMap.get(name);
    if (!prev) continue;
    if (curr.riskScore !== prev.riskScore || curr.riskLevel !== prev.riskLevel) {
      const arrow = curr.riskScore > prev.riskScore ? "↑ WORSE" : "↓ BETTER";
      console.log(
        `  ~ ${arrow}  ${name}: ${prev.riskScore}→${curr.riskScore} (${prev.riskLevel}→${curr.riskLevel})`
      );
      changes++;
    }
  }

  if (changes === 0) console.log("  No changes since last report.");
  console.log();
}

// ─── --fail-on support (CI exit codes) ────────────────────────────────────────
// failOn: high → exit 1 if any High; medium → High or Medium; low → any score > 0.

const LEVEL_RANK = { Low: 1, Medium: 2, High: 3 };

function shouldFail(results, failOn) {
  if (!failOn) return false;
  const threshold = LEVEL_RANK[failOn[0].toUpperCase() + failOn.slice(1)] || 0;
  if (failOn.toLowerCase() === "low") {
    return results.some((r) => r.riskScore > 0 && !r.isWhitelisted);
  }
  return results.some(
    (r) => !r.isWhitelisted && (LEVEL_RANK[r.riskLevel] || 0) >= threshold
  );
}

// ─── Save report ──────────────────────────────────────────────────────────────

const SAVE_EXT = {
  markdown: ".md",
  md: ".md",
  json: ".json",
  sarif: ".sarif",
  html: ".html",
  csv: ".csv",
  text: ".txt",
};

function saveReportToDisk(reportText, results, mode) {
  try {
    fs.mkdirSync(REPORTS_DIR, { recursive: true });

    const date = new Date().toISOString().slice(0, 10);
    const ext = SAVE_EXT[mode] || ".txt";
    const file = path.join(REPORTS_DIR, `${date}${ext}`);

    const content =
      mode === "json" || mode === "sarif" ? reportText : reportText;
    fs.writeFileSync(file, content, "utf8");
    console.error(`\nReport saved → ${file}`);
    return file;
  } catch (err) {
    console.error(`\nCould not save report: ${err.message}`);
    return null;
  }
}

// ─── --list-rules ─────────────────────────────────────────────────────────────

function listRules() {
  const rows = RULES.map(
    (r) =>
      `  [${r.id.padEnd(4)}] ${r.level.padEnd(6)} +${String(r.score).padEnd(
        2
      )}  ${r.label}`
  );
  return `Security Auditor rules (v${PKG_VERSION} — ${RULES.length} checks)\n\n${rows.join(
    "\n"
  )}\n`;
}

module.exports = {
  riskEmoji,
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
};
