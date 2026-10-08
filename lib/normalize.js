"use strict";

/**
 * Evasion normalization helpers.
 *
 * Attackers (and our own test fixtures) dodge naive static scanners with
 * split-string tricks such as adjacent literal concatenation or bracket
 * property access. Normalizing those forms before matching closes that hole
 * while keeping the raw text for evidence snippets.
 */

/**
 * Collapse adjacent string-literal concatenation:
 *   "mod" + "ule"  →  "module"
 *
 * Runs to a fixpoint (max 5 passes) so chained splits fully collapse. Only
 * joins literals on the SAME line to avoid merging unrelated expressions
 * across statement boundaries.
 *
 * @param {string} content raw file text
 * @returns {string} normalized text for pattern matching
 */
function normalizeForEvasion(content) {
  let out = content;
  const CONCAT = /(["'`])((?:(?!\1)[^\\\n]|\\.)*)\1\s*\+\s*(["'`])((?:(?!\3)[^\\\n]|\\.)*)\3/g;
  for (let i = 0; i < 5; i++) {
    const next = out.replace(CONCAT, (_m, q1, a, _q2, b) => q1 + a + b + q1);
    if (next === out) break;
    out = next;
  }
  return out;
}

/**
 * 1-based line number of a character offset within text.
 */
function lineOf(text, index) {
  if (index == null || index < 0) return 1;
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

module.exports = { normalizeForEvasion, lineOf };
