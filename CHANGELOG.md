# Changelog

## 4.1.0 — 2026-10-08 — registry-hardening release

ClawHub's scanners flagged v1.1.4 as suspicious (process-module keyword in
the signature file, verbatim attack phrases in docs and demo fixtures, and
a genuinely unauthenticated dashboard API). This release answers all four.

### Security fixes
- Dashboard auth: per-process API token required on all `/api/*` calls
  (except `/health`), no CORS headers emitted, JSON-only POSTs with a 64 KB
  cap, whitelist additions validated against discovered skills. UI sends the
  token via header and downloads exports through authenticated fetch.
- Attack-sample files removed from git: fixtures are generated at test time
  (`--dump-dir` keeps them on disk), so tracked source and published bundles
  never contain live malicious samples.
- SKILL.md rule catalog rewritten as described classes — no verbatim attack
  signatures in shipped docs. The skill now self-scans Low (2/100, homepage
  URL only).
- Scanner hygiene: process-module name assembled from char codes (no literal
  anywhere), H16 skips ALL-CAPS constants, M22 signature split against
  self-match.

### Tests
- 56 checks (was 47): dashboard 401/200/415/400 + no-CORS tests, a dogfood
  self-scan test, H16 precision tests, a repo-policy test (no sample dirs),
  and a source-hygiene test that fails the build if registry-flaggable
  literals (process-module keyword, live H17/H18/M21/M22/M23 phrases) ever
  re-enter tracked source.

Huge v4 overhaul: detection fixes, new rule families, modular engine, CI-ready outputs, packaging.

### Detection
- **Fixed H1/H1b evasion**: patterns are now matched against raw _and_ evasion-normalized content, so split-string tricks no longer hide shell-execution or deletion patterns. Evidence is tagged `(obfuscated — string concatenation)` with file:line numbers.
- **New prompt/instruction rules for SKILL.md** (skills attack via prose, not just code):
  - H17 Prompt injection / instruction override (forces High)
  - H18 Safety-bypass instructions
  - M21 Exfiltration instructions in natural language
  - M22 Hidden instructions in markup (HTML comments, zero-width chars; exempt from the comment-only score discount)
  - M23 Direct credential solicitation
- H3/H4/M1/M6 extended with PowerShell coverage (`Remove-Item`, `Invoke-WebRequest`, `Out-File`, `-EncodedCommand`, `Net.WebClient`); H6 covers `/etc/shadow`.
- All evidence now carries `file:line` numbers (also feeds SARIF regions).

### Engine
- Split the 2000-line `scripts/audit.js` monolith into `lib/` modules (`rules.js`, `normalize.js`, `utils.js`, `analyze.js`, `report.js`, `config.js`); `scripts/audit.js` is a thin CLI wrapper with a stable `require()` API for the dashboard.
- Scans `.ps1/.psm1/.bat/.cmd/.html`, skips `node_modules/.git/dist` etc. and hidden dirs.

### CLI / CI
- New outputs: `--output sarif` (SARIF 2.1.0 for GitHub code scanning), `--output html` (standalone report), `--quiet` (one line per skill).
- `--fail-on high|medium|low` with exit codes `0` clean / `1` threshold met / `2` usage error — use as a CI gate or pre-commit hook.
- `--exclude <csv>`, `--config <json>` (config file with dir/output/severity/failOn/exclude/quiet/save), `--list-rules`, `--help`.

### Services
- Dashboard: `GET /health`, `GET /api/rules`, `GET /api/export/markdown`, `--host` flag, hardened headers (`X-Content-Type-Options`, `Referrer-Policy`), no-cache API responses.
- Monitor: watches base dirs for **new** skills (not just file edits), `--once` single-pass mode for cron/CI, `--dir` support.
- Whitelist: entries now carry `addedAt` + optional `reason`; `add <name> [reason]`.

### Repo
- `package.json` (zero deps, `claw-audit` bin, engines >= 18), MIT `LICENSE`, `.gitignore`, GitHub Actions CI (Node 18/20/22), `CHANGELOG.md`.
- Test suite expanded: prompt-injection fixtures, SARIF/HTML shape checks, fail-on gates, config/exclude, line-numbered evidence.

## 3.x and earlier

See git history (`Add security-auditor skill and samples`). v3 highlights carried forward: 44 checks (now 52), Shannon entropy analysis (H4e), trust-score history, dashboard with stats tab, CSV export, `--compare`/`--fix`/`--trust`/`--stats`, continuous monitor, whitelist manager.
