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

import { existsSync, readFileSync } from "node:fs";
import { buildSchema, validateSchema } from "graphql";

const sdlFile = process.argv[2];

if (!sdlFile) {
  console.error("INVALID: no SDL file argument");
  process.exit(2);
}

if (!existsSync(sdlFile)) {
  console.error(`INVALID: SDL file not found: ${sdlFile}`);
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
