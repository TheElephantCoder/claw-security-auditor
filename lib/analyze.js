"use strict";

/**
 * Core static-analysis engine (v4).
 * Never executes skill code — reads and pattern-matches only.
 */

const path = require("path");

const { RULES, FORCE_HIGH_IDS } = require("./rules");
const { normalizeForEvasion, lineOf } = require("./normalize");
const {
  readSkillFiles,
  parseFrontmatter,
  isInComment,
  loadWhitelist,
  loadTrustDB,
  saveTrustDB,
} = require("./utils");

let ENGINE_VERSION = "4.0.0";
try {
  ENGINE_VERSION = require("../package.json").version || ENGINE_VERSION;
} catch {
  /* package.json not present (dev checkout) — keep default */
}

// ─── Rule application ────────────────────────────────────────────────────────

/**
 * Apply a single rule against all files of a skill.
 * Each pattern is tested against the raw content AND the
 * evasion-normalized content (string-concat tricks collapsed).
 * Returns { triggered, score, evidence[] }.
 * Evidence format: "file:line: `snippet`" with an optional
 * " (obfuscated — string concatenation)" marker when the hit only
 * appears after normalization.
 */
function applyRule(rule, files) {
  if (rule.patterns.length === 0)
    return { triggered: false, score: 0, evidence: [] };

  const allMatches = [];

  for (const file of files) {
    if (file.unreadable) continue;

    const normalized = normalizeForEvasion(file.content);
    const normalizedDiffers = normalized !== file.content;

    for (const pattern of rule.patterns) {
      const flags = pattern.flags.includes("g")
        ? pattern.flags
        : pattern.flags + "g";

      // 1) raw content
      collectMatches(pattern, flags, file.content, false, file, allMatches);
      // 2) normalized content (only when normalization changed something,
      //    to avoid duplicate work/noise)
      if (normalizedDiffers) {
        collectMatches(pattern, flags, normalized, true, file, allMatches);
      }
    }
  }

  if (allMatches.length === 0)
    return { triggered: false, score: 0, evidence: [] };

  const allInComments = allMatches.every((m) => m.inComment);
  // Rules that hunt for things hidden in markup must not be discounted
  // for living in comments — that is their entire point.
  const effectiveScore =
    allInComments && !rule.noCommentDiscount
      ? Math.round(rule.score * 0.5)
      : rule.score;

  // Deduplicate: raw and normalized searches can surface the same logical
  // hit (same file/line/snippet). Prefer the raw (non-evaded) entry.
  const best = new Map(); // key → match
  for (const m of allMatches) {
    const key = `${m.file}:${m.line}:${m.snippet}`;
    const prev = best.get(key);
    if (!prev || (prev.evaded && !m.evaded)) best.set(key, m);
  }
  const evidenceSet = new Set(
    [...best.values()].map((m) => {
      let tag = "";
      if (m.evaded) tag += " (obfuscated — string concatenation)";
      else if (m.inComment) tag += " (comment — lower confidence)";
      return `${m.file}:${m.line}: \`${m.snippet}\`${tag}`;
    })
  );

  return {
    triggered: true,
    score: effectiveScore,
    evidence: [...evidenceSet].slice(0, 5), // cap at 5 evidence items per rule
    allInComments,
  };
}

function collectMatches(pattern, flags, text, evaded, file, out) {
  const gPattern = new RegExp(pattern.source, flags);
  const seen = new Set();
  let m;

  while ((m = gPattern.exec(text)) !== null) {
    // Avoid infinite loops on zero-length matches
    if (m[0].length === 0) {
      gPattern.lastIndex++;
      continue;
    }

    const snippet = m[0].slice(0, 80).replace(/\s+/g, " ").trim();
    const line = lineOf(text, m.index);
    const key = `${file.filePath}:${snippet}`;
    if (seen.has(key)) continue;
    seen.add(key);

    out.push({
      file: path.basename(file.filePath),
      line,
      snippet,
      // Comment position is only meaningful for raw text; for normalized
      // hits, check the equivalent raw position.
      inComment: evaded ? false : isInComment(file.content, m.index),
      evaded,
    });
  }
}

// ─── Cross-file exfiltration detection ───────────────────────────────────────
// M3 bonus: if ANY file reads local files AND any file makes network calls,
// flag the combination even if they are in separate scripts.

function detectCrossFileExfiltration(files) {
  // tokens split to avoid self-match when this file is scanned
  const fileReadPatterns = [
    new RegExp("\\bfs\\.read" + "File\\b"),
    new RegExp("\\bfs\\.read" + "FileSync\\b"),
    /\bopen\s*\([^)]+,\s*['"]r['"]/,
    /\bos\.walk\b/,
    /\bglob\b/,
  ];
  const networkPatterns = [
    /\bfetch\s*\(/,
    /\baxios\b/,
    /\burllib\b/,
    /\brequests\s*\.\s*(get|post)/,
    /https?\s*\.\s*(get|request)\s*\(/,
  ];

  const hasFileRead = files.some(
    (f) => !f.unreadable && fileReadPatterns.some((p) => p.test(f.content))
  );
  const hasNetwork = files.some(
    (f) => !f.unreadable && networkPatterns.some((p) => p.test(f.content))
  );

  return hasFileRead && hasNetwork;
}

// ─── Shannon entropy analysis ─────────────────────────────────────────────────
// High entropy strings (>4.5 bits/char) in script files often indicate
// embedded secrets, encoded payloads, or obfuscated data.

function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Extract candidate high-entropy strings: quoted strings ≥ 20 chars
const HIGH_ENTROPY_PATTERN = /['"`]([A-Za-z0-9+/=_\-]{20,})['"`]/g;
const ENTROPY_THRESHOLD = 4.5;

function detectHighEntropyStrings(files) {
  const hits = [];
  for (const file of files) {
    if (file.unreadable) continue;
    if (
      ![".js", ".mjs", ".ts", ".py", ".sh", ".bash", ".json", ".env"].includes(
        file.ext
      )
    )
      continue;

    const gp = new RegExp(HIGH_ENTROPY_PATTERN.source, "g");
    let m;
    while ((m = gp.exec(file.content)) !== null) {
      const candidate = m[1];
      const entropy = shannonEntropy(candidate);
      if (
        entropy >= ENTROPY_THRESHOLD &&
        !isInComment(file.content, m.index)
      ) {
        hits.push({
          file: path.basename(file.filePath),
          line: lineOf(file.content, m.index),
          snippet: candidate.slice(0, 40) + (candidate.length > 40 ? "…" : ""),
          entropy: entropy.toFixed(2),
        });
        if (hits.length >= 3) return hits; // cap at 3 to avoid noise
      }
    }
  }
  return hits;
}

// ─── Core analysis engine ────────────────────────────────────────────────────

function analyzeSkill(skill) {
  const files = readSkillFiles(skill.location);
  const skillMdFile = files.find((f) => f.filePath === skill.skillPath);
  const skillMd = skillMdFile ? skillMdFile.content : "";
  const frontmatter = parseFrontmatter(skillMd);
  const claimedPerms = Array.isArray(frontmatter.permissions)
    ? frontmatter.permissions
    : [];

  const triggeredRules = [];
  let rawScore = 0;

  const unreadableFiles = files.filter((f) => f.unreadable);
  if (unreadableFiles.length > 0) {
    const penalty = unreadableFiles.length * 15;
    rawScore += penalty;
    triggeredRules.push({
      id: "UNREADABLE",
      level: "High",
      score: penalty,
      label: "Unreadable files",
      evidence: unreadableFiles.map((f) => path.basename(f.filePath)),
    });
  }

  // Apply all pattern-based rules
  for (const rule of RULES) {
    if (rule.patterns.length === 0) continue;

    const result = applyRule(rule, files);
    if (!result.triggered) continue;

    triggeredRules.push({
      id: rule.id,
      level: rule.level,
      score: result.score,
      label: rule.label,
      evidence: result.evidence,
    });
    rawScore += result.score;
  }

  // ── M3 cross-file exfiltration (bonus detection) ──────────────────────────
  const alreadyHasM3 = triggeredRules.some((r) => r.id === "M3");
  if (!alreadyHasM3 && detectCrossFileExfiltration(files)) {
    triggeredRules.push({
      id: "M3",
      level: "Medium",
      score: 20,
      label: "Data exfiltration pattern",
      evidence: [
        "Cross-file: file read operations + outbound network calls detected in same skill",
      ],
    });
    rawScore += 20;
  }

  // ── M5: Permission mismatch ───────────────────────────────────────────────
  const dangerousPerms = new Set([
    "exec:shell",
    "write:filesystem",
    "read:secrets",
    "network:unrestricted",
    "admin",
  ]);
  const benignKeywords =
    /\b(weather|logs?|format|date|time|convert|translate|search|lookup)\b/i;
  const description = frontmatter.description || "";

  if (
    claimedPerms.some((p) => dangerousPerms.has(p)) &&
    benignKeywords.test(description)
  ) {
    triggeredRules.push({
      id: "M5",
      level: "Medium",
      score: 10,
      label: "Excessive permission claims",
      evidence: [
        `Claims [${claimedPerms
          .filter((p) => dangerousPerms.has(p))
          .join(", ")}] but description suggests benign use`,
      ],
    });
    rawScore += 10;
  }

  // ── L4: Sparse documentation ──────────────────────────────────────────────
  // Strip frontmatter before counting words
  const bodyText = skillMd.replace(/^---[\s\S]*?---\r?\n/, "");
  const bodyWordCount = bodyText.trim().split(/\s+/).filter(Boolean).length;
  if (bodyWordCount < 50) {
    triggeredRules.push({
      id: "L4",
      level: "Low",
      score: 5,
      label: "Sparse documentation",
      evidence: [
        `SKILL.md body has only ${bodyWordCount} words (threshold: 50)`,
      ],
    });
    rawScore += 5;
  }

  // ── L10: Large file size anomaly ──────────────────────────────────────────
  const LARGE_FILE_THRESHOLD = 500 * 1024; // 500 KB
  const largeFiles = files.filter(
    (f) =>
      !f.unreadable &&
      [".js", ".mjs", ".ts", ".py", ".sh", ".bash", ".ps1"].includes(f.ext) &&
      Buffer.byteLength(f.content, "utf8") > LARGE_FILE_THRESHOLD
  );
  if (largeFiles.length > 0) {
    const sizes = largeFiles.map(
      (f) =>
        `${path.basename(f.filePath)} (${Math.round(
          Buffer.byteLength(f.content, "utf8") / 1024
        )}KB)`
    );
    triggeredRules.push({
      id: "L10",
      level: "Low",
      score: 5,
      label: "Large file size anomaly",
      evidence: sizes,
    });
    rawScore += 5;
  }

  // ── High-entropy string detection ─────────────────────────────────────────
  // Complements H4 — catches secrets/payloads not caught by base64 patterns
  const alreadyHasH4 = triggeredRules.some((r) => r.id === "H4");
  if (!alreadyHasH4) {
    const entropyHits = detectHighEntropyStrings(files);
    if (entropyHits.length > 0) {
      triggeredRules.push({
        id: "H4e",
        level: "High",
        score: 20,
        label: "High-entropy strings (possible embedded secret/payload)",
        evidence: entropyHits.map(
          (h) =>
            `${h.file}:${h.line}: "${h.snippet}" (entropy ${h.entropy} bits/char)`
        ),
      });
      rawScore += 20;
    }
  }

  // ── Whitelist suppression ─────────────────────────────────────────────────
  const whitelist = loadWhitelist();
  const isWhitelisted = whitelist.trusted.includes(skill.name);

  // ── Score capping and level assignment ────────────────────────────────────
  const finalScore = Math.min(rawScore, 100);
  const forceHigh = triggeredRules.some((r) => FORCE_HIGH_IDS.includes(r.id));

  let riskLevel;
  if (forceHigh || finalScore >= 60) riskLevel = "High";
  else if (finalScore >= 30) riskLevel = "Medium";
  else riskLevel = "Low";

  // ── Trust score update ────────────────────────────────────────────────────
  const trustScore = updateTrustScore(skill.name, finalScore, riskLevel);

  return {
    name: skill.name,
    location: skill.location,
    riskScore: finalScore,
    riskLevel,
    isWhitelisted,
    trustScore,
    frontmatter,
    triggeredRules,
    scoreBreakdown: triggeredRules.map((r) => ({
      id: r.id,
      label: r.label,
      score: r.score,
    })),
    behaviors: deriveDetectedBehaviors(triggeredRules, files),
    threats: derivePotentialThreats(triggeredRules),
    simulation:
      finalScore >= 30
        ? generateMaliciousSimulation(triggeredRules, skill.name)
        : null,
    recommendations: generateRecommendations(
      triggeredRules,
      finalScore,
      riskLevel
    ),
    fileCount: files.length,
    unreadableCount: unreadableFiles.length,
    scannedAt: new Date().toISOString(),
    engineVersion: ENGINE_VERSION,
  };
}

// ─── Trust score system ───────────────────────────────────────────────────────
// Each time a skill is scanned, its history is recorded.
// Trust score = 100 - (weighted average of last 5 risk scores).
// A skill that consistently scores 0 earns trust score 100.

function updateTrustScore(skillName, riskScore, riskLevel) {
  const db = loadTrustDB();
  const history = db[skillName] || { scans: [] };

  history.scans.push({
    date: new Date().toISOString().slice(0, 10),
    riskScore,
    riskLevel,
  });

  // Keep last 10 scans
  if (history.scans.length > 10) history.scans = history.scans.slice(-10);

  // Weighted average: more recent scans count more
  const scans = history.scans;
  let weightedSum = 0;
  let totalWeight = 0;
  scans.forEach((s, i) => {
    const weight = i + 1; // older = lower weight
    weightedSum += s.riskScore * weight;
    totalWeight += weight;
  });

  const avgRisk = totalWeight > 0 ? weightedSum / totalWeight : riskScore;
  history.trust = Math.round(Math.max(0, 100 - avgRisk));
  history.scanCount = scans.length;

  db[skillName] = history;
  saveTrustDB(db);

  return { score: history.trust, scanCount: history.scanCount, history: scans };
}

function showTrustReport() {
  const db = loadTrustDB();
  if (Object.keys(db).length === 0) {
    console.log("No trust history yet. Run an audit first.");
    return;
  }

  console.log("\nTRUST SCORE HISTORY\n" + "─".repeat(50));
  for (const [name, data] of Object.entries(db)) {
    const bar =
      "█".repeat(Math.round(data.trust / 10)) +
      "░".repeat(10 - Math.round(data.trust / 10));
    const trend = getTrend(data.scans);
    console.log(`\n${name}`);
    console.log(`  Trust Score : ${data.trust}/100  ${bar}  ${trend}`);
    console.log(`  Scans       : ${data.scanCount}`);
    if (data.scans.length > 0) {
      const last = data.scans[data.scans.length - 1];
      console.log(
        `  Last Scan   : ${last.date} — Risk ${last.riskScore}/100 (${last.riskLevel})`
      );
    }
  }
  console.log();
}

function getTrend(scans) {
  if (scans.length < 2) return "→ (not enough data)";
  const prev = scans[scans.length - 2].riskScore;
  const curr = scans[scans.length - 1].riskScore;
  if (curr < prev) return "↓ improving";
  if (curr > prev) return "↑ worsening";
  return "→ stable";
}

// ─── Behavior derivation ──────────────────────────────────────────────────────

function deriveDetectedBehaviors(rules, files) {
  const behaviors = [];
  const ruleIds = new Set(rules.map((r) => r.id));

  if (ruleIds.has("H1") || ruleIds.has("H1b"))
    behaviors.push("Executes shell commands");
  if (ruleIds.has("H2")) behaviors.push("Downloads and executes remote code");
  if (ruleIds.has("H3")) behaviors.push("Deletes files from the filesystem");
  if (ruleIds.has("H4")) behaviors.push("Contains obfuscated or encoded logic");
  if (ruleIds.has("H5")) behaviors.push("Attempts privilege escalation");
  if (ruleIds.has("H6"))
    behaviors.push("Accesses credential stores or secret files");
  if (ruleIds.has("H7"))
    behaviors.push("Reads .env files (potential secret exposure)");
  if (ruleIds.has("M1")) behaviors.push("Makes outbound network requests");
  if (ruleIds.has("M2"))
    behaviors.push("Reads from sensitive system directories");
  if (ruleIds.has("M3"))
    behaviors.push("Read-then-send pattern (data exfiltration risk)");
  if (ruleIds.has("M4")) behaviors.push("Constructs and runs code dynamically");
  if (ruleIds.has("M5"))
    behaviors.push("Claims permissions beyond stated functionality");
  if (ruleIds.has("M6"))
    behaviors.push("Writes files outside expected working directory");
  if (ruleIds.has("M7"))
    behaviors.push("Contains potential denial-of-service patterns");
  if (ruleIds.has("H8"))
    behaviors.push("Captures keyboard input (potential keylogger)");
  if (ruleIds.has("H9")) behaviors.push("Accesses system clipboard");
  if (ruleIds.has("H10"))
    behaviors.push("Captures screenshots or screen content");
  if (ruleIds.has("H11")) behaviors.push("Contains crypto mining indicators");
  if (ruleIds.has("H12"))
    behaviors.push("Contains reverse shell / backdoor patterns");
  if (ruleIds.has("H13")) behaviors.push("Manipulates Windows registry");
  if (ruleIds.has("H14"))
    behaviors.push("Installs persistence mechanism (cron/launchd/startup)");
  if (ruleIds.has("M8"))
    behaviors.push("Accesses browser cookies or local storage");
  if (ruleIds.has("M9"))
    behaviors.push("Opens WebSocket connection (potential C2 channel)");
  if (ruleIds.has("M10"))
    behaviors.push("Performs DNS lookups or hostname resolution");
  if (ruleIds.has("M11")) behaviors.push("Enumerates running processes");
  if (ruleIds.has("M12")) behaviors.push("Enumerates network interfaces");
  if (ruleIds.has("M13"))
    behaviors.push("Archives files before sending (exfiltration staging)");
  if (ruleIds.has("M14"))
    behaviors.push("Uses long sleep delays (timing/evasion pattern)");
  if (ruleIds.has("M15"))
    behaviors.push("Modifies or deletes itself (self-modification)");
  if (ruleIds.has("M16"))
    behaviors.push("Accesses cloud instance metadata endpoint (IMDS)");
  if (ruleIds.has("L1")) behaviors.push("Sends telemetry to external service");
  if (ruleIds.has("L2")) behaviors.push("Calls third-party APIs");
  if (ruleIds.has("L3")) behaviors.push("Reads environment variables");
  if (ruleIds.has("L4")) behaviors.push("Sparse or missing documentation");
  if (ruleIds.has("L5"))
    behaviors.push("Contains hardcoded URLs or IP addresses");
  if (ruleIds.has("L6"))
    behaviors.push("Contains security-related TODO/FIXME notes");
  if (ruleIds.has("L7")) behaviors.push("Uses weak cryptographic algorithms");
  if (ruleIds.has("L8"))
    behaviors.push("Makes insecure HTTP (non-TLS) connections");
  if (ruleIds.has("L9"))
    behaviors.push(
      "Contains debug artifacts (debugger, pdb, sensitive console.log)"
    );
  if (ruleIds.has("L10"))
    behaviors.push(
      "Contains unusually large script files (possible embedded payload)"
    );
  if (ruleIds.has("H4e"))
    behaviors.push(
      "Contains high-entropy strings (possible embedded secret or payload)"
    );
  if (ruleIds.has("H15"))
    behaviors.push(
      "Constructs SQL or shell commands via string concatenation"
    );
  if (ruleIds.has("H16"))
    behaviors.push(
      "Installs or loads packages at runtime (supply-chain risk)"
    );
  if (ruleIds.has("M17"))
    behaviors.push(
      "Modifies object prototypes (prototype pollution risk)"
    );
  if (ruleIds.has("M18"))
    behaviors.push(
      "Constructs file paths from user input (path traversal risk)"
    );
  if (ruleIds.has("M19"))
    behaviors.push("Deserializes untrusted data (unsafe deserialization)");
  if (ruleIds.has("M20"))
    behaviors.push("Contains hardcoded credentials or API keys");
  if (ruleIds.has("H17"))
    behaviors.push(
      "Contains prompt-injection / instruction-override text (agent hijack risk)"
    );
  if (ruleIds.has("H18"))
    behaviors.push("Instructs the agent to bypass safety controls");
  if (ruleIds.has("M21"))
    behaviors.push(
      "Instructions describe sending sensitive data externally"
    );
  if (ruleIds.has("M22"))
    behaviors.push("Contains hidden instructions in markup/comments");
  if (ruleIds.has("M23"))
    behaviors.push("Asks the user for passwords, keys, or secrets directly");

  const scriptFiles = files.filter((f) =>
    [".js", ".mjs", ".ts", ".py", ".sh", ".bash", ".ps1"].includes(f.ext)
  );
  if (scriptFiles.length > 0) {
    behaviors.push(`Includes ${scriptFiles.length} executable script file(s)`);
  }

  if (behaviors.length === 0)
    behaviors.push("No suspicious behaviors detected");
  return behaviors;
}

// ─── Threat derivation ────────────────────────────────────────────────────────

function derivePotentialThreats(rules) {
  const threats = [];
  const ruleIds = new Set(rules.map((r) => r.id));

  if (ruleIds.has("H1") || ruleIds.has("H1b"))
    threats.push("Arbitrary OS command execution on the host machine");
  if (ruleIds.has("H2"))
    threats.push("Supply chain attack via remote payload execution");
  if (ruleIds.has("H3"))
    threats.push("Irreversible data loss through file deletion");
  if (ruleIds.has("H4"))
    threats.push("Hidden malicious payload concealed by obfuscation");
  if (ruleIds.has("H5"))
    threats.push("Full system compromise via privilege escalation");
  if (ruleIds.has("H6"))
    threats.push("Theft of SSH keys, API tokens, or cloud credentials");
  if (ruleIds.has("H7"))
    threats.push("Exposure of secrets stored in .env files");
  if (ruleIds.has("M1") && ruleIds.has("M2"))
    threats.push("Sensitive file contents leaked to external server");
  if (ruleIds.has("M3"))
    threats.push("Automated data exfiltration of local files");
  if (ruleIds.has("M4"))
    threats.push("Runtime code injection via dynamic execution");
  if (ruleIds.has("M6"))
    threats.push("Tampering with OpenClaw config or system files");
  if (ruleIds.has("M7"))
    threats.push("Agent or system resource exhaustion (DoS)");
  if (ruleIds.has("H8"))
    threats.push(
      "Keystroke logging — passwords and sensitive input captured silently"
    );
  if (ruleIds.has("H9"))
    threats.push(
      "Clipboard theft — copied passwords, tokens, or secrets exfiltrated"
    );
  if (ruleIds.has("H10"))
    threats.push(
      "Screen capture — visual data, credentials on screen, or private content stolen"
    );
  if (ruleIds.has("H11"))
    threats.push(
      "Unauthorized use of host CPU/GPU for cryptocurrency mining"
    );
  if (ruleIds.has("H12"))
    threats.push(
      "Full remote access to the host machine via reverse shell or backdoor"
    );
  if (ruleIds.has("H13"))
    threats.push(
      "Persistent malware installation via Windows registry Run key"
    );
  if (ruleIds.has("H14"))
    threats.push(
      "Skill survives reboots via cron/launchd/systemd persistence — hard to remove"
    );
  if (ruleIds.has("M8"))
    threats.push("Browser session hijacking via cookie or localStorage theft");
  if (ruleIds.has("M9"))
    threats.push(
      "Command-and-control (C2) channel via persistent WebSocket connection"
    );
  if (ruleIds.has("M13") && ruleIds.has("M1"))
    threats.push("Files archived and uploaded — bulk exfiltration of local data");
  if (ruleIds.has("M16"))
    threats.push(
      "Cloud credential theft via IMDS — IAM tokens, instance identity, and secrets exposed"
    );
  if (ruleIds.has("L7"))
    threats.push(
      "Weak hashing (MD5/SHA1) may allow hash collision or brute-force attacks"
    );
  if (ruleIds.has("L3"))
    threats.push("Exposure of secrets stored in environment variables");
  if (ruleIds.has("H4e"))
    threats.push(
      "High-entropy strings may be embedded secrets, tokens, or encoded payloads"
    );
  if (ruleIds.has("H15"))
    threats.push(
      "SQL/command injection — attacker-controlled input may execute arbitrary queries or commands"
    );
  if (ruleIds.has("H16"))
    threats.push(
      "Runtime package installation enables supply-chain attacks via malicious or typosquatted packages"
    );
  if (ruleIds.has("M17"))
    threats.push(
      "Prototype pollution may corrupt shared objects and enable privilege escalation in Node.js"
    );
  if (ruleIds.has("M18"))
    threats.push(
      "Path traversal may allow reading or writing files outside the intended directory"
    );
  if (ruleIds.has("M19"))
    threats.push(
      "Unsafe deserialization of attacker-controlled data can lead to remote code execution"
    );
  if (ruleIds.has("M20"))
    threats.push(
      "Hardcoded credentials exposed in source code — anyone with read access can steal them"
    );
  if (ruleIds.has("H17"))
    threats.push(
      "Agent hijack — prompt-injection text can make the agent ignore safety rules and follow attacker instructions"
    );
  if (ruleIds.has("H18"))
    threats.push(
      "Safety controls disabled by instruction — destructive or exfiltrating actions run without user approval"
    );
  if (ruleIds.has("M21"))
    threats.push(
      "Instruction-driven exfiltration — the agent may be talked into uploading sensitive data"
    );
  if (ruleIds.has("M22"))
    threats.push(
      "Hidden directives invisible in normal rendering may steer agent behavior without reviewer awareness"
    );
  if (ruleIds.has("M23"))
    threats.push(
      "Credential phishing — users may paste live secrets into chat where they are logged or forwarded"
    );

  if (threats.length === 0) threats.push("No significant threats identified");
  return threats;
}

// ─── Malicious simulation ─────────────────────────────────────────────────────

function generateMaliciousSimulation(rules, skillName) {
  const scenarios = [];
  const ruleIds = new Set(rules.map((r) => r.id));

  if (ruleIds.has("H2")) {
    scenarios.push(
      `A malicious "${skillName}" could fetch a payload from an attacker-controlled server ` +
        `and execute it directly — installing a backdoor or ransomware with no user interaction ` +
        `beyond invoking the skill.`
    );
  }
  if (ruleIds.has("H6") && ruleIds.has("M1")) {
    scenarios.push(
      `The credential access + outbound HTTP combination means "${skillName}" could silently ` +
        `read ~/.ssh/id_rsa, ~/.aws/credentials, or API tokens and POST them to a remote server ` +
        `in a single invocation.`
    );
  }
  if (ruleIds.has("H3") && (ruleIds.has("H1") || ruleIds.has("H1b"))) {
    scenarios.push(
      `Shell execution + file deletion means "${skillName}" could run a recursive delete ` +
        `against the home directory or selectively wipe project files, databases, or SSH ` +
        `keys with no recovery path.`
    );
  }
  if (ruleIds.has("H4")) {
    scenarios.push(
      `The obfuscated logic in "${skillName}" could decode and execute any arbitrary payload ` +
        `at runtime. True behavior is hidden from static analysis — treat as untrusted until ` +
        `the obfuscated section is manually reviewed.`
    );
  }
  if (ruleIds.has("M3")) {
    scenarios.push(
      `The read-then-send pattern in "${skillName}" could enumerate files in ~/Documents or ` +
        `~/Desktop and silently upload them to an external endpoint, exfiltrating source code, ` +
        `personal data, or business documents.`
    );
  }
  if (ruleIds.has("H5")) {
    scenarios.push(
      `Privilege escalation patterns in "${skillName}" could gain root access, install ` +
        `persistent system-level malware, or modify system host files and binaries.`
    );
  }
  if (ruleIds.has("H7")) {
    scenarios.push(
      `"${skillName}" reads .env files — a malicious version could harvest all secrets ` +
        `(API keys, DB passwords, tokens) and exfiltrate them via the network calls already present.`
    );
  }
  if (ruleIds.has("M7")) {
    scenarios.push(
      `The infinite loop or aggressive process.exit patterns in "${skillName}" could be ` +
        `triggered to hang or crash the OpenClaw agent process, causing a denial of service.`
    );
  }
  if (ruleIds.has("H8")) {
    scenarios.push(
      `The keylogger patterns in "${skillName}" could silently record every keystroke — ` +
        `capturing passwords, API keys, and private messages typed anywhere on the system ` +
        `while the skill is active.`
    );
  }
  if (ruleIds.has("H9") && ruleIds.has("M1")) {
    scenarios.push(
      `"${skillName}" reads the clipboard AND makes outbound network calls. A malicious ` +
        `version could poll the clipboard for copied passwords or crypto wallet addresses ` +
        `and silently exfiltrate them.`
    );
  }
  if (ruleIds.has("H10")) {
    scenarios.push(
      `The screen capture capability in "${skillName}" could take periodic screenshots ` +
        `and upload them to a remote server, leaking everything visible on screen — ` +
        `including browser sessions, documents, and credentials.`
    );
  }
  if (ruleIds.has("H11")) {
    scenarios.push(
      `"${skillName}" contains crypto mining indicators. If weaponized, it could spawn ` +
        `a miner process that consumes 100% CPU/GPU indefinitely, degrading ` +
        `system performance and increasing electricity costs.`
    );
  }
  if (ruleIds.has("H12")) {
    scenarios.push(
      `The reverse shell patterns in "${skillName}" could open a persistent connection ` +
        `to an attacker's server, granting full interactive shell access to the host machine ` +
        `with the same privileges as the running process.`
    );
  }
  if (ruleIds.has("H14")) {
    scenarios.push(
      `"${skillName}" installs a persistence mechanism. Even if the skill is removed, ` +
        `the cron job, launchd plist, or startup entry it created would continue running ` +
        `malicious code on every login or reboot.`
    );
  }
  if (ruleIds.has("M16")) {
    scenarios.push(
      `"${skillName}" queries the cloud instance metadata endpoint (169.254.169.254). ` +
        `On AWS/GCP/Azure, this can retrieve IAM credentials, instance identity tokens, ` +
        `and user-data secrets — enabling full cloud account takeover.`
    );
  }
  if (ruleIds.has("M13") && ruleIds.has("M1")) {
    scenarios.push(
      `"${skillName}" archives files AND makes outbound network calls. A malicious version ` +
        `could zip ~/Documents or source code directories and upload the archive to an ` +
        `attacker-controlled server in a single operation.`
    );
  }
  if (ruleIds.has("H15")) {
    scenarios.push(
      `The SQL/command injection patterns in "${skillName}" mean that if any user-controlled ` +
        `input reaches these code paths, an attacker could execute arbitrary database queries ` +
        `or OS commands — dumping data, dropping tables, or gaining shell access.`
    );
  }
  if (ruleIds.has("H16")) {
    scenarios.push(
      `"${skillName}" installs packages at runtime. A malicious version could install a ` +
        `typosquatted or compromised package that runs a postinstall script with full OS access, ` +
        `completely bypassing static analysis.`
    );
  }
  if (ruleIds.has("M20")) {
    scenarios.push(
      `"${skillName}" contains hardcoded credentials. Anyone who reads the source code — ` +
        `including via a public repo, a log file, or a compromised backup — immediately has ` +
        `access to those credentials with no further attack required.`
    );
  }
  if (ruleIds.has("M19")) {
    scenarios.push(
      `The unsafe deserialization in "${skillName}" could allow an attacker to craft a ` +
        `malicious serialized payload that, when deserialized, executes arbitrary code — ` +
        `a classic RCE vector in Python pickle and Node.js serialize libraries.`
    );
  }
  if (ruleIds.has("H17")) {
    scenarios.push(
      `The prompt-injection text in "${skillName}" could hijack the agent: once the skill ` +
        `is loaded, the agent may ignore its safety instructions and follow the attacker's ` +
        `directives — exfiltrating data or running destructive actions as if the user asked.`
    );
  }
  if (ruleIds.has("H18")) {
    scenarios.push(
      `"${skillName}" tells the agent to skip confirmations or disable the sandbox. ` +
        `Combined with any file or network capability, destructive actions would run ` +
        `silently with no chance for the user to intervene.`
    );
  }
  if (ruleIds.has("M21")) {
    scenarios.push(
      `The exfiltration phrasing in "${skillName}" normalizes sending sensitive data out. ` +
        `A user following the skill's instructions could paste secrets into an upload ` +
        `that goes straight to an attacker-controlled endpoint.`
    );
  }
  if (ruleIds.has("M22")) {
    scenarios.push(
      `Hidden markup in "${skillName}" is invisible in rendered Markdown but fully visible ` +
        `to the agent. Reviewers see a benign skill while the agent receives extra orders.`
    );
  }

  if (scenarios.length === 0) {
    scenarios.push(
      `With its current permission set, a malicious "${skillName}" could abuse its access ` +
        `to leak data or disrupt local workflows, though the attack surface is limited.`
    );
  }

  return scenarios;
}

// ─── Recommendations ──────────────────────────────────────────────────────────

function generateRecommendations(rules, score, level) {
  const recs = [];
  const ruleIds = new Set(rules.map((r) => r.id));

  if (
    score >= 80 ||
    ruleIds.has("H2") ||
    ruleIds.has("H4") ||
    ruleIds.has("H17")
  ) {
    recs.push(
      "DISABLE immediately — risk is critical. Remove or quarantine this skill."
    );
  }
  if (ruleIds.has("H1") || ruleIds.has("H1b") || ruleIds.has("H2")) {
    recs.push(
      "Run in Docker sandbox mode to isolate shell execution from the host OS."
    );
  }
  if (ruleIds.has("H6") || ruleIds.has("H7")) {
    recs.push(
      "Rotate any credentials or API tokens this skill could have accessed."
    );
  }
  if (ruleIds.has("M5")) {
    recs.push(
      "Edit SKILL.md metadata — remove permissions not required by the skill's stated purpose."
    );
  }
  if (ruleIds.has("M3") || ruleIds.has("M1")) {
    recs.push("Verify all outbound HTTP destinations are expected and trusted.");
  }
  if (ruleIds.has("M4")) {
    recs.push("Replace dynamic code execution with static logic where possible.");
  }
  if (ruleIds.has("H3")) {
    recs.push(
      "Scope file deletion to a specific temp directory; never allow arbitrary path deletion."
    );
  }
  if (ruleIds.has("M7")) {
    recs.push(
      "Review loop termination conditions and process.exit() calls for abuse potential."
    );
  }
  if (ruleIds.has("H8")) {
    recs.push(
      "DISABLE immediately — keylogger patterns detected. Audit all input handling code."
    );
  }
  if (ruleIds.has("H9")) {
    recs.push(
      "Verify clipboard access is necessary; if not, remove it. Never send clipboard contents externally."
    );
  }
  if (ruleIds.has("H10")) {
    recs.push(
      "Screen capture capability requires explicit user consent. Verify this is intentional and disclosed."
    );
  }
  if (ruleIds.has("H11")) {
    recs.push(
      "DISABLE immediately — crypto mining indicators detected. Remove and quarantine this skill."
    );
  }
  if (ruleIds.has("H12")) {
    recs.push(
      "DISABLE immediately — reverse shell patterns detected. This skill may be a backdoor."
    );
  }
  if (ruleIds.has("H13")) {
    recs.push(
      "Registry manipulation requires explicit justification. Audit all registry keys being modified."
    );
  }
  if (ruleIds.has("H14")) {
    recs.push(
      "Persistence mechanisms must be disclosed to the user. Audit and remove any unauthorized startup entries."
    );
  }
  if (ruleIds.has("M9")) {
    recs.push(
      "Audit WebSocket endpoints — persistent connections can serve as C2 channels."
    );
  }
  if (ruleIds.has("M13")) {
    recs.push(
      "File archiving before network calls is a strong exfiltration signal — verify the destination."
    );
  }
  if (ruleIds.has("M16")) {
    recs.push(
      "Block access to 169.254.169.254 at the network level if running in cloud environments."
    );
  }
  if (ruleIds.has("L7")) {
    recs.push(
      "Replace MD5/SHA1 with SHA-256 or stronger. Never use Math.random() for security-sensitive values."
    );
  }
  if (ruleIds.has("L8")) {
    recs.push(
      "Replace http:// URLs with https:// to prevent man-in-the-middle attacks."
    );
  }
  if (ruleIds.has("L9")) {
    recs.push(
      "Remove debug artifacts (debugger, pdb.set_trace, sensitive console.log) before production use."
    );
  }
  if (ruleIds.has("H4e")) {
    recs.push(
      "Audit high-entropy strings — they may be hardcoded secrets. Move to environment variables or a secrets manager."
    );
  }
  if (ruleIds.has("H15")) {
    recs.push(
      "Use parameterized queries / prepared statements. Never concatenate user input into SQL or shell commands."
    );
  }
  if (ruleIds.has("H16")) {
    recs.push(
      "Pin all dependencies to exact versions. Never install packages at runtime from user-controlled input."
    );
  }
  if (ruleIds.has("M17")) {
    recs.push(
      "Validate and sanitize all user-supplied keys before merging into objects. Use Object.create(null) for safe maps."
    );
  }
  if (ruleIds.has("M18")) {
    recs.push(
      "Resolve and validate all file paths against an allowed base directory. Reject paths containing '..'."
    );
  }
  if (ruleIds.has("M19")) {
    recs.push(
      "Replace pickle.loads / yaml.load with safe alternatives (json, yaml.safe_load). Never deserialize untrusted data."
    );
  }
  if (ruleIds.has("M20")) {
    recs.push(
      "Remove hardcoded credentials immediately. Rotate the exposed secrets and store them in environment variables or a vault."
    );
  }
  if (ruleIds.has("H17") || ruleIds.has("H18")) {
    recs.push(
      "Remove the instruction-override language from SKILL.md. If the capability is legitimate, rephrase it as a user-confirmed step instead of an standing order."
    );
  }
  if (ruleIds.has("M22")) {
    recs.push(
      "Delete hidden markup/comments carrying instructions. All agent directives must be visible in rendered documentation."
    );
  }
  if (ruleIds.has("M21") || ruleIds.has("M23")) {
    recs.push(
      "Never ask users for live secrets in chat. Use environment variables, a secrets manager, or OAuth device flow instead."
    );
  }
  if (
    level === "Low" &&
    rules.filter((r) => r.id !== "L3" && r.id !== "L5").length === 0
  ) {
    recs.push(
      "No action required. Consider adding to whitelist to suppress future alerts."
    );
  }
  if (recs.length === 0) {
    recs.push(
      "Review flagged patterns manually before trusting this skill in production."
    );
  }

  return recs;
}

module.exports = {
  ENGINE_VERSION,
  applyRule,
  detectCrossFileExfiltration,
  shannonEntropy,
  detectHighEntropyStrings,
  analyzeSkill,
  updateTrustScore,
  showTrustReport,
  getTrend,
  deriveDetectedBehaviors,
  derivePotentialThreats,
  generateMaliciousSimulation,
  generateRecommendations,
};
