#!/usr/bin/env node
/**
 * OpenClaw Security Auditor — Dashboard Server (v4.1).
 *
 * Serves a local web UI at http://localhost:7777 (or $PORT).
 * No external dependencies — uses Node.js built-in http module only.
 * Binds to loopback by default; use --host to override (know the risks).
 *
 * Security model (hardened per ClawHub AIG T09 review):
 * - No CORS headers are emitted: the UI is same-origin vanilla JS, so
 *   cross-origin pages cannot read API responses at all.
 * - Every /api/* endpoint (except /health) requires a per-process token
 *   in the X-Audit-Token header. The token is generated at startup and
 *   embedded only in the locally served UI page — it never appears in
 *   logs, URLs, or CORS responses, so other origins cannot learn it.
 * - State-changing POSTs additionally require Content-Type:
 *   application/json, a 64 KB body cap, and (for whitelist/add) a skill
 *   name that actually exists in the discovered skill set.
 *
 * Usage:
 *   node scripts/dashboard.js
 *   node scripts/dashboard.js --dir ./demo-skills
 *   node scripts/dashboard.js --port 8080
 *   node scripts/dashboard.js --host 127.0.0.1
 *   node scripts/dashboard.js --no-open   # don't auto-open browser
 */

"use strict";

const http   = require("http");
const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");
const os     = require("os");

const { discoverSkills } = require("../lib/utils");
const { analyzeSkill } = require("../lib/analyze");
const { loadTrustDB, loadWhitelist, sysProc } = require("../lib/utils");
const {
  formatCSVReport,
  formatMarkdownReport,
} = require("../lib/report");
const { RULES, RULES_VERSION } = require("../lib/rules");

// ─── CLI args ─────────────────────────────────────────────────────────────────
const args     = process.argv.slice(2);
const PORT     = parseInt(argValue(args, "--port") || process.env.PORT || "7777", 10);
const HOST     = argValue(args, "--host") || process.env.HOST || "127.0.0.1";
const NO_OPEN  = args.includes("--no-open");
const extraDir = argValue(args, "--dir") ? path.resolve(argValue(args, "--dir")) : null;

function argValue(arr, flag) {
  const i = arr.indexOf(flag);
  return i !== -1 ? arr[i + 1] : null;
}

const UI_FILE = path.join(__dirname, "..", "ui", "index.html");

// ─── Per-process API token ────────────────────────────────────────────────────
// Generated fresh on every boot; embedded only in the served UI page.

const API_TOKEN = crypto.randomBytes(32).toString("hex");

function checkAuth(req) {
  const presented = req.headers["x-audit-token"];
  if (typeof presented !== "string") return false;
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(API_TOKEN, "utf8");
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// ─── Scan helper ──────────────────────────────────────────────────────────────

function runScan() {
  const skills  = discoverSkills(extraDir);
  const results = skills.map(skill => {
    try {
      return analyzeSkill(skill);
    } catch (err) {
      return {
        name: skill.name, location: skill.location,
        riskScore: 50, riskLevel: "Medium",
        isWhitelisted: false, trustScore: { score: 50, scanCount: 0 },
        frontmatter: {}, triggeredRules: [],
        behaviors: [`Analysis error: ${err.message}`],
        threats: ["Could not complete analysis — treat as untrusted"],
        simulation: null,
        recommendations: ["Manually inspect this skill — automated analysis failed"],
        fileCount: 0, unreadableCount: 0,
        scannedAt: new Date().toISOString(),
      };
    }
  });
  return results;
}

function ruleFrequency(results) {
  const ruleFreq = {};
  const ruleLabel = {};
  for (const r of results) {
    for (const rule of r.triggeredRules) {
      ruleFreq[rule.id]  = (ruleFreq[rule.id] || 0) + 1;
      ruleLabel[rule.id] = rule.label;
    }
  }
  const sorted = Object.entries(ruleFreq)
    .sort((a, b) => b[1] - a[1])
    .map(([id, count]) => ({ id, label: ruleLabel[id], count, pct: results.length ? Math.round((count / results.length) * 100) : 0 }));
  const avgScore = results.length
    ? Math.round(results.reduce((s, r) => s + r.riskScore, 0) / results.length)
    : 0;
  return { total: results.length, avgScore, rules: sorted };
}

// ─── Minimal HTTP router ──────────────────────────────────────────────────────

const MAX_BODY_BYTES = 64 * 1024;

const server = http.createServer((req, res) => {
  const url = req.url.split("?")[0];

  // No CORS headers are emitted on purpose: the UI is same-origin, and
  // cross-origin callers must not be able to read API responses.
  // Hardening headers (UI is same-origin vanilla JS; no external resources)
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");

  const isApi = url.startsWith("/api/");
  if (isApi) res.setHeader("Cache-Control", "no-store");

  const json = (code, obj) => {
    res.writeHead(code, { "Content-Type": "application/json" });
    res.end(JSON.stringify(obj));
  };

  // ── GET /health (unauthenticated liveness only) ──────────────────────────
  if (req.method === "GET" && url === "/health") {
    return json(200, { ok: true, version: RULES_VERSION, rules: RULES.length });
  }

  // ── GET / — serve the UI with the per-process token embedded ────────────
  if (req.method === "GET" && (url === "/" || url === "/index.html")) {
    try {
      const html = fs.readFileSync(UI_FILE, "utf8").replaceAll("__CLAW_AUDIT_TOKEN__", API_TOKEN);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
    } catch {
      res.writeHead(500);
      res.end("UI file not found. Expected: " + UI_FILE);
    }
    return;
  }

  // ── Everything else under /api/* requires the token ─────────────────────
  if (isApi && !checkAuth(req)) {
    return json(401, { error: "Missing or invalid X-Audit-Token." });
  }

  // ── State-changing requests must be JSON ─────────────────────────────────
  if (req.method === "POST") {
    const ctype = (req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
    if (ctype !== "application/json") {
      return json(415, { error: "Content-Type must be application/json." });
    }
  }

  // ── GET /api/rules — full rule catalog ───────────────────────────────────
  if (req.method === "GET" && url === "/api/rules") {
    return json(200, {
      version: RULES_VERSION,
      rules: RULES.map(r => ({ id: r.id, level: r.level, score: r.score, label: r.label })),
    });
  }

  // ── GET /api/scan — run full audit, return JSON ───────────────────────────
  if (req.method === "GET" && url === "/api/scan") {
    try {
      const results = runScan();
      return json(200, results);
    } catch (err) {
      return json(500, { error: err.message });
    }
  }

  // ── POST /api/scan/single { name } — re-scan one skill ───────────────────
  if (req.method === "POST" && url === "/api/scan/single") {
    readBody(req, (body) => {
      if (body === null) return json(413, { error: "Request body too large." });
      try {
        const { name } = JSON.parse(body);
        const skills   = discoverSkills(extraDir);
        const skill    = skills.find(s => s.name === name);
        if (!skill) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Skill not found: ${name}` }));
          return;
        }
        const result = analyzeSkill(skill);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // ── GET /api/stats — rule frequency analytics ─────────────────────────────
  if (req.method === "GET" && url === "/api/stats") {
    try {
      const results = runScan();
      return json(200, ruleFrequency(results));
    } catch (err) {
      return json(500, { error: err.message });
    }
  }

  // ── GET /api/export/csv — CSV download ────────────────────────────────────
  if (req.method === "GET" && url === "/api/export/csv") {
    try {
      const results = runScan();
      const csv     = formatCSVReport(results);
      res.writeHead(200, {
        "Content-Type": "text/csv",
        "Content-Disposition": `attachment; filename="openclaw-audit-${new Date().toISOString().slice(0,10)}.csv"`,
      });
      res.end(csv);
    } catch (err) {
      return json(500, { error: err.message });
    }
    return;
  }

  // ── GET /api/export/markdown — Markdown download ──────────────────────────
  if (req.method === "GET" && url === "/api/export/markdown") {
    try {
      const results = runScan();
      const md      = formatMarkdownReport(results);
      res.writeHead(200, {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": `attachment; filename="openclaw-audit-${new Date().toISOString().slice(0,10)}.md"`,
      });
      res.end(md);
    } catch (err) {
      return json(500, { error: err.message });
    }
    return;
  }

  // ── GET /api/trust — trust score history ─────────────────────────────────
  if (req.method === "GET" && url === "/api/trust") {
    try {
      const db = loadTrustDB();
      return json(200, db);
    } catch (err) {
      return json(500, { error: err.message });
    }
  }

  // ── GET /api/whitelist — current whitelist ────────────────────────────────
  if (req.method === "GET" && url === "/api/whitelist") {
    try {
      const wl = loadWhitelist();
      return json(200, wl);
    } catch (err) {
      return json(500, { error: err.message });
    }
  }

  // ── POST /api/whitelist/add  { name } ─────────────────────────────────────
  if (req.method === "POST" && url === "/api/whitelist/add") {
    readBody(req, (body) => {
      if (body === null) return json(413, { error: "Request body too large." });
      try {
        const { name } = JSON.parse(body);
        if (!name || typeof name !== "string") throw new Error("Missing skill name.");
        // Only real, currently discovered skills can be whitelisted.
        const skills = discoverSkills(extraDir);
        if (!skills.some(s => s.name === name)) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Unknown skill: ${name}` }));
          return;
        }
        const wlPath   = path.join(os.homedir(), ".openclaw", "security-auditor-whitelist.json");
        const wl       = loadWhitelist();
        if (!wl.trusted.includes(name)) {
          wl.trusted.push(name);
          wl.meta = wl.meta || {};
          wl.meta[name] = { addedAt: new Date().toISOString().slice(0, 10), reason: "via dashboard" };
          wl.updatedAt = new Date().toISOString();
          fs.mkdirSync(path.dirname(wlPath), { recursive: true });
          fs.writeFileSync(wlPath, JSON.stringify(wl, null, 2));
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, trusted: wl.trusted }));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // ── POST /api/whitelist/remove  { name } ──────────────────────────────────
  if (req.method === "POST" && url === "/api/whitelist/remove") {
    readBody(req, (body) => {
      if (body === null) return json(413, { error: "Request body too large." });
      try {
        const { name } = JSON.parse(body);
        const wlPath   = path.join(os.homedir(), ".openclaw", "security-auditor-whitelist.json");
        const wl       = loadWhitelist();
        wl.trusted     = wl.trusted.filter(s => s !== name);
        if (wl.meta) delete wl.meta[name];
        wl.updatedAt   = new Date().toISOString();
        fs.mkdirSync(path.dirname(wlPath), { recursive: true });
        fs.writeFileSync(wlPath, JSON.stringify(wl, null, 2));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, trusted: wl.trusted }));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

function readBody(req, cb) {
  let data = "";
  let tooLarge = false;
  req.on("data", chunk => {
    if (tooLarge) return;
    data += chunk;
    if (Buffer.byteLength(data, "utf8") > MAX_BODY_BYTES) {
      tooLarge = true;
    }
  });
  req.on("end", () => cb(tooLarge ? null : data));
}

// ─── Start ────────────────────────────────────────────────────────────────────

server.listen(PORT, HOST, () => {
  const addr = server.address();
  const host = typeof addr === "object" && addr ? addr.address : HOST;
  const port = typeof addr === "object" && addr ? addr.port : PORT;
  const url = `http://${host}:${port}`;
  console.log(`\nOpenClaw Security Auditor Dashboard`);
  console.log(`────────────────────────────────────`);
  console.log(`Listening on ${url}`);
  if (HOST !== "127.0.0.1" && HOST !== "localhost") {
    console.log(`⚠️  Bound to non-loopback host — restrict network access!`);
  }
  console.log(`Press Ctrl+C to stop.\n`);

  if (!NO_OPEN) openBrowser(url);
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`Port ${PORT} is already in use. Try --port <number>.`);
  } else {
    console.error("Server error:", err.message);
  }
  process.exit(1);
});

function openBrowser(url) {
  const { execSync } = sysProc();
  const cmds = { darwin: `open "${url}"`, win32: `start "${url}"`, linux: `xdg-open "${url}"` };
  const cmd  = cmds[process.platform];
  if (cmd) {
    try { execSync(cmd); } catch { /* ignore — user can open manually */ }
  }
}
