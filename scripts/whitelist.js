#!/usr/bin/env node
/**
 * OpenClaw Security Auditor — Whitelist Manager (v4).
 *
 * Tracks trusted skills to suppress future alerts. Entries carry an
 * optional reason and timestamp for auditability.
 *
 * Usage:
 *   node whitelist.js add <skill-name> [reason]  # add to whitelist
 *   node whitelist.js remove <skill-name>        # remove from whitelist
 *   node whitelist.js list                       # show all whitelisted skills
 *   node whitelist.js check <skill-name>         # exit 0 if trusted, 1 if not
 */

"use strict";

const { loadWhitelist, saveWhitelist } = require("../lib/utils");

const [,, command, skillName, ...reasonParts] = process.argv;
const wl = loadWhitelist();
if (!wl.meta) wl.meta = {};

switch (command) {
  case "add": {
    if (!skillName) { console.error("Usage: whitelist.js add <skill-name> [reason]"); process.exit(1); }
    if (!wl.trusted.includes(skillName)) {
      wl.trusted.push(skillName);
      wl.meta[skillName] = {
        addedAt: new Date().toISOString().slice(0, 10),
        reason: reasonParts.join(" ") || null,
      };
      saveWhitelist(wl);
      console.log(`✅ "${skillName}" added to whitelist.`);
    } else {
      console.log(`"${skillName}" is already whitelisted.`);
    }
    break;
  }

  case "remove": {
    if (!skillName) { console.error("Usage: whitelist.js remove <skill-name>"); process.exit(1); }
    wl.trusted = wl.trusted.filter(s => s !== skillName);
    delete wl.meta[skillName];
    saveWhitelist(wl);
    console.log(`🗑  "${skillName}" removed from whitelist.`);
    break;
  }

  case "list": {
    if (wl.trusted.length === 0) {
      console.log("Whitelist is empty.");
    } else {
      console.log("Trusted skills:");
      wl.trusted.forEach(s => {
        const meta = wl.meta[s];
        const extra = meta && (meta.reason || meta.addedAt)
          ? `  (${[meta.addedAt, meta.reason].filter(Boolean).join(" — ")})`
          : "";
        console.log(`  • ${s}${extra}`);
      });
    }
    break;
  }

  case "check": {
    if (!skillName) { console.error("Usage: whitelist.js check <skill-name>"); process.exit(1); }
    process.exit(wl.trusted.includes(skillName) ? 0 : 1);
  }

  default:
    console.error("Commands: add | remove | list | check");
    process.exit(1);
}
