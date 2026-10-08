# Security Auditor — OpenClaw Skill

Autonomously scans all installed OpenClaw skills for security risks using
static analysis. No skill code is ever executed.

 v4 adds: **prompt-injection detection** (H17/H18/M21–M23), **evasion-resistant
matching** (string-concat tricks like `"child" + "_process"` are normalized
before matching), **SARIF + HTML reports**, **CI gates** (`--fail-on` with
exit codes), a modular `lib/` engine, and full packaging (`package.json`,
MIT license, GitHub Actions CI).

## Installation

```bash
# Copy to your OpenClaw skills directory
cp -r security-auditor ~/.openclaw/skills/security-auditor

# Or for workspace-local use
cp -r security-auditor ./skills/security-auditor
```

No dependencies — pure Node.js stdlib (`node >= 18`). There is nothing to `npm install`.

```bash
node scripts/test.js   # run the self-test suite (47 checks, no network)
```

## Publishing to ClawHub

Build a clean, publish-ready skill folder (dev-only fixtures, sample
skills, and CI config are excluded per `.clawhubignore` — the sample
skills are intentionally risky demos and must not ship to the registry):

```bash
npm run pack
# → dist/security-auditor/  (SKILL.md + lib/ + scripts/ + ui/ + docs)
```

Then publish with the ClawHub CLI:

```bash
clawhub login
clawhub skill publish ./dist/security-auditor \
  --slug security-auditor \
  --version 4.0.0 \
  --categories security,development \
  --topics "security-scan,static-analysis,prompt-injection,sarif,skill-safety"
```

## Dashboard (GUI)

Run the local web dashboard for a visual risk overview:

```bash
node scripts/dashboard.js
# or point at a specific skills directory:
node scripts/dashboard.js --dir data/sample-skills
# custom port / host:
node scripts/dashboard.js --port 8080
node scripts/dashboard.js --host 127.0.0.1
# skip auto-opening the browser:
node scripts/dashboard.js --no-open
```

Opens `http://localhost:7777` automatically. No build step, no npm install — pure Node.js stdlib on the server, vanilla JS in the browser. Binds to loopback by default.

Features:

- Live risk summary (total / high / medium / low counts)
- Expandable skill cards with score ring, triggered rules, threats, simulation, recommendations
- Trust score bar + risk trend sparkline per skill
- Score breakdown per rule, stats tab with rule-frequency chart
- Filter by risk level, search by name, behavior, or rule ID/label
- Whitelist toggle directly from the UI (re-scans automatically)
- CSV + Markdown export buttons, `R` keyboard shortcut to rescan

API endpoints: `GET /health`, `GET /api/scan`, `POST /api/scan/single`,
`GET /api/stats`, `GET /api/rules`, `GET /api/export/csv`,
`GET /api/export/markdown`, `GET /api/trust`, `GET/POST /api/whitelist/*`.

Once installed, just ask your agent:

```
"Audit all my installed skills"
"Are my skills safe?"
"Run a security scan on the file-cleaner skill"
"Give me a security report"
```

## Usage via CLI (direct)

```bash
# Scan all skills (default paths)
node scripts/audit.js

# Scan a specific directory of skills
node scripts/audit.js --dir data/sample-skills

# Scan a single skill by name
node scripts/audit.js --dir data/sample-skills --skill file-cleaner

# Output formats
node scripts/audit.js --dir data/sample-skills --output json      # machine-readable
node scripts/audit.js --dir data/sample-skills --output markdown  # Markdown report
node scripts/audit.js --dir data/sample-skills --output csv       # CSV export
node scripts/audit.js --dir data/sample-skills --output sarif     # SARIF 2.1.0 (GitHub code scanning)
node scripts/audit.js --dir data/sample-skills --output html      # standalone HTML report
node scripts/audit.js --dir data/sample-skills --quiet            # one line per skill (CI logs)

# Filter by severity / skip skills
node scripts/audit.js --severity high         # only High risk skills
node scripts/audit.js --exclude vendor,legacy # skip matching names/paths

# Load defaults from a JSON config file (CLI flags win)
node scripts/audit.js --config audit.config.json

# CI gate: exit 1 when findings meet the threshold (0 clean, 1 tripped, 2 error)
node scripts/audit.js --dir data/sample-skills --fail-on high

# Save report to ~/.openclaw/security-reports/
node scripts/audit.js --dir data/sample-skills --save

# Compare against last saved report (shows what changed)
node scripts/audit.js --dir data/sample-skills --compare

# Auto-generate patched SKILL.md with dangerous permissions stripped
node scripts/audit.js --dir data/sample-skills --fix

# Show trust score history for all skills
node scripts/audit.js --trust

# Show rule-frequency analytics
node scripts/audit.js --dir data/sample-skills --stats

# List all 52 detection rules
node scripts/audit.js --list-rules

# Manage the whitelist (optional reason is recorded)
node scripts/whitelist.js add weather-lookup "official sample, reviewed"
node scripts/whitelist.js list
node scripts/whitelist.js remove weather-lookup

# Continuous monitoring (background watcher)
node scripts/monitor.js
node scripts/monitor.js --alert-only   # only print on High risk
node scripts/monitor.js --once         # single pass, then exit (cron/CI)

# Run the test suite
node scripts/test.js   # or: npm test
```

Example `audit.config.json`:

```json
{
  "dir": "./skills",
  "output": "text",
  "severity": null,
  "failOn": "high",
  "exclude": ["bundled-"],
  "quiet": false,
  "save": false
}
```

### GitHub code scanning (SARIF)

```bash
node scripts/audit.js --dir ./skills --output sarif > audit.sarif
gh code-scanning upload-sarif audit.sarif
```

### CI gate example (GitHub Actions)

```yaml
- run: node scripts/audit.js --dir ./skills --fail-on high --quiet
```

## Testing with sample skills

```bash
node scripts/audit.js --dir data/sample-skills
```

> **Note:** `data/sample-skills/` contains intentionally risky demo scripts used
> to validate the auditor's detection rules. They are not needed for normal use
> and can be safely deleted if you do not want potentially dangerous demo code on disk:
> ```bash
> rm -rf data/sample-skills
> ```
>
> `data/test-fixtures/` holds extra cases for the test suite: `shady-helper`
> (prompt-injection demo: H17/H18/M21/M22/M23) and `clean-minimal` (scores 0).

See `data/example-output.md` for expected output against the three sample skills.

## Continuous monitoring (optional, advanced)

> ⚠️ **This is an optional feature.** Running the monitor as a background service
> means it will continuously read skill files and run on every login. Only enable
> this if you have reviewed the code and are comfortable with that behavior.

Run the monitor script in the background to auto-audit whenever a skill file changes
(or a new skill is installed — base directories are watched too):

```bash
node scripts/monitor.js
# or, only alert on High risk findings:
node scripts/monitor.js --alert-only
# or, a single pass for cron/CI:
node scripts/monitor.js --once --dir ./skills
```

If you choose to run it automatically on login, the recipes below show how.
**Review the code first and only proceed if you trust the package source.**

**launchd (macOS)** — create `~/Library/LaunchAgents/com.openclaw.security-monitor.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.openclaw.security-monitor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/node</string>
    <string>/path/to/security-auditor/scripts/monitor.js</string>
    <string>--alert-only</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/tmp/openclaw-monitor.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/openclaw-monitor.log</string>
</dict>
</plist>
```
Then: `launchctl load ~/Library/LaunchAgents/com.openclaw.security-monitor.plist`

**systemd (Linux)** — create `~/.config/systemd/user/openclaw-monitor.service`:
```ini
[Unit]
Description=OpenClaw Security Monitor

[Service]
ExecStart=/usr/bin/node /path/to/security-auditor/scripts/monitor.js --alert-only
Restart=on-failure

[Install]
WantedBy=default.target
```
Then: `systemctl --user enable --now openclaw-monitor`

## Risk scoring

| Score | Level  | Meaning                                      |
|-------|--------|----------------------------------------------|
| 0–29  | 🟢 Low  | Benign — review optional                    |
| 30–59 | 🟡 Medium | Warrants manual review before trusting    |
| 60+   | 🔴 High | Disable or sandbox immediately              |

H2 (remote code execute), H4 (obfuscation), or H17 (prompt injection) always
forces High regardless of score.

Comment-only matches score 50% (lower confidence) — except M22, which hunts
for instructions hidden in markup by design.

## Architecture

```
security-auditor/
├── SKILL.md                    ← Agent instructions + metadata
├── README.md / CHANGELOG.md    ← Docs
├── package.json / LICENSE      ← Packaging (zero deps, node >= 18)
├── lib/
│   ├── rules.js                ← 52 detection rules + force-high IDs
│   ├── normalize.js            ← evasion normalization (string-concat collapse)
│   ├── utils.js                ← discovery, file reading, frontmatter, stores
│   ├── analyze.js              ← analysis engine (scores, sims, recommendations)
│   ├── report.js               ← text/markdown/csv/sarif/html/quiet formatters
│   └── config.js               ← JSON config file loader
├── scripts/
│   ├── audit.js                ← Thin CLI (stable require() API for dashboard)
│   ├── dashboard.js            ← Local web dashboard server
│   ├── whitelist.js            ← Whitelist manager (reasons + timestamps)
│   ├── monitor.js              ← Continuous file watcher (+ --once, new-skill watch)
│   └── test.js                 ← Self-test suite (47 checks)
├── ui/
│   └── index.html              ← Dashboard UI (self-contained, no build step)
└── data/
    ├── example-output.md       ← Sample report output
    ├── sample-skills/          ← Demo skills for testing
    │   ├── file-cleaner/       ← High risk example (evasion techniques)
    │   ├── data-sync/          ← Medium risk example
    │   └── weather-lookup/     ← Low risk (clean) example
    └── test-fixtures/          ← Extra engine test cases
        ├── shady-helper/       ← Prompt-injection demo (H17/H18/M21–M23)
        └── clean-minimal/      ← Benign fixture (scores 0)
```

## Detection rules (v4)

52 checks across 3 risk levels + prompt/instruction risks:

High risk (H1–H18): shell execution (+ evasion variants: bracket alias,
template-literal exec, concat normalization), remote code download, file
deletion (+ PowerShell `Remove-Item`), obfuscation (+ `-EncodedCommand`),
privilege escalation, credential harvesting, .env access, keyloggers, clipboard
theft, screen capture, crypto mining, reverse shells, registry manipulation,
persistence mechanisms, SQL/command injection, supply-chain/runtime package
install, **prompt injection / instruction override (H17)**, **safety-bypass
instructions (H18)**

Medium risk (M1–M23): network calls (+ PowerShell web clients), sensitive
directory access, data exfiltration, dynamic eval, permission mismatch, unscoped
writes, DoS patterns, browser storage, WebSocket C2, DNS lookups, process
enumeration, network enumeration, file archiving/staging, timing evasion,
self-modification, cloud IMDS access, prototype pollution, path traversal,
unsafe deserialization, hardcoded credentials, **natural-language exfiltration
instructions (M21)**, **hidden instructions in markup (M22)**,
**credential solicitation (M23)**

Low risk (L1–L10): telemetry, third-party APIs, env var reads, sparse docs,
hardcoded URLs, security TODOs, weak crypto, insecure HTTP, debug artifacts,
large file anomaly

Plus: Shannon entropy analysis (H4e) — detects high-entropy strings that may be embedded secrets or encoded payloads

Run `node scripts/audit.js --list-rules` (or `GET /api/rules`) for the full
catalog with scores.

## New in v4

- Evasion-resistant matching: string-concatenation obfuscation is normalized
  before matching; hits tagged `(obfuscated — string concatenation)`
- Prompt/instruction rules H17/H18/M21/M22/M23 for SKILL.md prose attacks
- `--output sarif` (GitHub code scanning) and `--output html`
- `--quiet`, `--fail-on high|medium|low` (exit 0/1/2) for CI gates
- `--exclude`, `--config <json>`, `--list-rules`, `--help`
- `file:line` evidence everywhere (feeds SARIF regions)
- PowerShell script coverage (`.ps1/.psm1/.bat/.cmd/.html` scanned)
- Monitor watches for newly installed skills + `--once` mode
- Dashboard: `/health`, `/api/rules`, Markdown export, `--host`, hardened headers
- Whitelist reasons + timestamps; `package.json`, MIT license, CI, changelog
- 47-test suite incl. prompt-injection fixtures and SARIF/fail-on/config tests

v2/v3 features carried forward: `--dir`, Markdown/CSV reports, `--compare`,
`--fix`, `--trust`, `--stats`, `--severity`, entropy analysis, `scoreBreakdown`
in JSON, dashboard stats tab / sparklines / CSV export / `R` shortcut /
single-skill rescan.

## Constraints

- Static analysis only — no skill code is ever executed
- Read-only — never modifies or deletes skill files (`--fix` only writes new `SKILL.patched.md` files)
- No external dependencies — pure Node.js stdlib
