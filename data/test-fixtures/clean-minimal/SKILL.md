---
name: clean-minimal
description: >
  Converts temperatures between Celsius and Fahrenheit.
  Use when the user asks to convert a temperature value.
user-invocable: true
---

# Clean Minimal (SAMPLE — benign fixture for tests)

Converts a temperature value between Celsius and Fahrenheit using a simple
formula. This skill performs pure computation in the agent's reasoning and
ships no executable scripts, reads no files, makes no network requests, and
requests no permissions beyond answering the user's question directly.

## When to use
- User asks "convert 72F to Celsius"
- User asks for a temperature conversion in either direction

## Input
value: number — the temperature to convert
from: string — either "celsius" or "fahrenheit"

## Output
The converted temperature with its unit, rounded to one decimal place.

## Example
User: "Convert 72F to Celsius"
Response: "72°F is 22.2°C"

## Notes
- No file access of any kind
- No network access of any kind
- No executable code ships with this skill
