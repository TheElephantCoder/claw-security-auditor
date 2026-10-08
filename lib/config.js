"use strict";

/**
 * Optional JSON config file (v4).
 *
 *   node scripts/audit.js --config ./audit.config.json
 *
 * Supported keys (all optional):
 *   { "dir": "./skills", "skill": null, "output": "text",
 *     "severity": "medium", "failOn": "high", "quiet": false,
 *     "exclude": ["bundled-"], "save": false }
 *
 * Explicit CLI flags always win over the config file.
 */

const fs = require("fs");
const path = require("path");

const VALID_OUTPUTS = new Set([
  "text",
  "markdown",
  "md",
  "json",
  "csv",
  "sarif",
  "html",
  "quiet",
]);
const VALID_LEVELS = new Set(["high", "medium", "low"]);

function loadConfigFile(configPath) {
  const resolved = path.resolve(configPath);
  let raw;
  try {
    raw = fs.readFileSync(resolved, "utf8");
  } catch (err) {
    throw new Error(`Cannot read config file ${resolved}: ${err.message}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in config file ${resolved}: ${err.message}`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Config file ${resolved} must contain a JSON object.`);
  }

  const cfg = {};
  if (typeof parsed.dir === "string") cfg.dir = parsed.dir;
  if (typeof parsed.skill === "string") cfg.skill = parsed.skill;
  if (typeof parsed.output === "string") {
    if (!VALID_OUTPUTS.has(parsed.output)) {
      throw new Error(
        `Config "output" must be one of: ${[...VALID_OUTPUTS].join(", ")}`
      );
    }
    cfg.output = parsed.output;
  }
  if (typeof parsed.severity === "string") {
    if (!VALID_LEVELS.has(parsed.severity.toLowerCase())) {
      throw new Error('Config "severity" must be high, medium, or low.');
    }
    cfg.severity = parsed.severity.toLowerCase();
  }
  if (typeof parsed.failOn === "string") {
    if (!VALID_LEVELS.has(parsed.failOn.toLowerCase())) {
      throw new Error('Config "failOn" must be high, medium, or low.');
    }
    cfg.failOn = parsed.failOn.toLowerCase();
  }
  if (typeof parsed.quiet === "boolean") cfg.quiet = parsed.quiet;
  if (typeof parsed.save === "boolean") cfg.save = parsed.save;
  if (Array.isArray(parsed.exclude)) {
    cfg.exclude = parsed.exclude.filter((x) => typeof x === "string");
  }
  return cfg;
}

module.exports = { loadConfigFile, VALID_OUTPUTS, VALID_LEVELS };
