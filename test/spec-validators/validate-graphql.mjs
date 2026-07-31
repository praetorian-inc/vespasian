#!/usr/bin/env node
// Copyright 2026 Praetorian Security, Inc.
//
// Real GraphQL SDL validator for the vespasian live-test suite (LAB-3890 T1).
// Replaces the old check, which passed any file containing the literal strings
// "type Query {" and "}" with length >= 50.
//
// Uses graphql-js (the reference implementation, already a hermetic dep of the
// live-test graphql-server):
//   * buildSchema()   -> parses the SDL and runs SDL-level validation; throws
//                        on syntax errors, duplicate types, unknown directives.
//   * validateSchema() -> schema-level validation; catches e.g. a missing/empty
//                        Query root type that buildSchema alone tolerates.
//
// Usage:   node validate-graphql.mjs <sdl_file>
// Exit 0 + "OK: ..." on a valid SDL; exit 1 + "INVALID: <reason>" otherwise.

import { existsSync, readFileSync, statSync } from "node:fs";
import { buildSchema, validateSchema } from "graphql";

// Cap the input before any parsing, so a pathological document cannot pin the
// parser. The sibling OpenAPI validator needs this because js-yaml has no
// maxAliasCount equivalent and YAML anchor/alias expansion is unbounded (a
// ~400-byte alias bomb expands exponentially and still exits 0 reporting "OK");
// the same bound is applied here so both validators refuse oversized input
// rather than only one. A wall-clock timeout on the shell side covers the
// expansion itself (PR #187 review finding SEC-FE-003).
//
// SPEC_VALIDATOR_MAX_BYTES overrides the default (mirroring
// SPEC_VALIDATOR_TIMEOUT in test/validate.sh). It exists so validate_test.sh can
// exercise the too-large rejection against a small fixture instead of having to
// generate a >5 MiB file. A value that is present but not a positive integer is
// a misconfiguration and is rejected outright rather than silently falling back
// to the default — a silently ignored override would let a test believe it had
// exercised the cap when it had not. Same variable as the sibling OpenAPI
// validator, so one setting bounds both.
const DEFAULT_MAX_SDL_BYTES = 5 * 1024 * 1024; // 5 MiB = 5242880

// Unset or empty -> the default. Anything else must be a positive base-10
// integer; non-numeric, zero, negative and fractional values all fail fast.
function resolveMaxBytes(raw) {
  if (raw === undefined || raw.trim() === "") return DEFAULT_MAX_SDL_BYTES;
  const value = raw.trim();
  const parsed = Number.parseInt(value, 10);
  if (!/^[0-9]+$/.test(value) || !Number.isSafeInteger(parsed) || parsed <= 0) {
    console.error(
      `INVALID: SPEC_VALIDATOR_MAX_BYTES must be a positive base-10 integer of bytes, got: "${raw}"`,
    );
    process.exit(2);
  }
  return parsed;
}

const MAX_SDL_BYTES = resolveMaxBytes(process.env.SPEC_VALIDATOR_MAX_BYTES);

const sdlFile = process.argv[2];

if (!sdlFile) {
  console.error("INVALID: no SDL file argument");
  process.exit(2);
}

if (!existsSync(sdlFile)) {
  console.error(`INVALID: SDL file not found: ${sdlFile}`);
  process.exit(1);
}

const sdlBytes = statSync(sdlFile).size;
if (sdlBytes > MAX_SDL_BYTES) {
  console.error(
    `INVALID: SDL file too large: ${sdlBytes} bytes (limit ${MAX_SDL_BYTES})`,
  );
  process.exit(1);
}

try {
  const sdl = readFileSync(sdlFile, "utf8");
  const schema = buildSchema(sdl); // throws on syntax / SDL-structure errors
  const errors = validateSchema(schema); // schema-level errors (e.g. no Query)
  if (errors.length > 0) {
    console.error(`INVALID: ${errors[0].message}`);
    process.exit(1);
  }
  const queryType = schema.getQueryType();
  const fieldCount = queryType ? Object.keys(queryType.getFields()).length : 0;
  console.log(`OK: valid GraphQL SDL (Query with ${fieldCount} fields)`);
  process.exit(0);
} catch (err) {
  const first = String(err && err.message ? err.message : err).split("\n")[0];
  console.error(`INVALID: ${first}`);
  process.exit(1);
}
