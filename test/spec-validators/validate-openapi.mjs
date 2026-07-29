#!/usr/bin/env node
// Copyright 2026 Praetorian Security, Inc.
//
// Real OpenAPI validator for the vespasian live-test suite (LAB-3890 T1).
// Replaces the old grep-for-top-level-keys check, which passed any file that
// merely contained the strings "openapi:", "info:" and "paths:" on a line.
//
// Uses @apidevtools/swagger-parser. What it actually enforces for the OpenAPI
// 3.x documents vespasian emits is narrower than it first appears:
//   * OpenAPI JSON-schema validation of the document structure -- enforced.
//   * Resolution of internal ($ref: "#/...") pointers, so a dangling internal
//     ref is a hard error -- enforced.
//   * Its semantic validateSpec() pass is a NO-OP here. validateSpec()
//     early-returns for any document carrying an `openapi` key (see
//     node_modules/@apidevtools/swagger-parser/lib/validators/spec.js:15-19,
//     "We don't (yet) support validating against the OpenAPI spec"), and
//     vespasian emits `openapi: 3.0.3`. So swagger-parser contributes NOTHING
//     toward duplicate operationIds, duplicate parameters, or path/body
//     parameter rules -- those checks only ever run for Swagger 2.0
//     (PR #187 review finding SEC-FE-001).
// Duplicate-operationId detection is a property this suite intends to prove
// (T1), so it is implemented explicitly below rather than assumed. YAML and
// JSON are both accepted. Fully offline once `npm ci` has run.
//
// Usage:   node validate-openapi.mjs <spec_file>
// Exit 0 + "OK: ..." on a valid spec; exit 1 + "INVALID: <reason>" otherwise.

import { existsSync, statSync } from "node:fs";
import SwaggerParser from "@apidevtools/swagger-parser";

// Cap the input before any parsing. js-yaml has no maxAliasCount equivalent, so
// YAML anchor/alias expansion is unbounded: a ~400-byte document with nested
// 9-way aliases expands exponentially (measured: 6 levels -> 1.4s, 7 -> 11.5s,
// 9 -> no return after 30s) and still exits 0 reporting "OK: valid spec". A
// size cap bounds the parser's input; a wall-clock timeout on the shell side
// bounds the expansion itself (PR #187 review finding SEC-FE-003).
const MAX_SPEC_BYTES = 5 * 1024 * 1024; // 5 MiB = 5242880

// The only keys in a Path Item Object that denote an operation. Everything else
// a path item may carry (parameters, summary, description, servers, $ref) is
// not an operation and must not be scanned for operationId.
const HTTP_METHODS = new Set([
  "get",
  "put",
  "post",
  "delete",
  "options",
  "head",
  "patch",
  "trace",
]);

// Walk an arbitrary parsed document for the first $ref that is not a local
// pointer. Every spec this validator sees is self-contained, so any external
// $ref is by definition a generator defect (SEC-FE-002). `seen` guards against
// YAML aliases producing shared or cyclic nodes, which would otherwise make
// this walk loop forever or blow up exponentially.
function findExternalRef(node, seen = new Set()) {
  if (node === null || typeof node !== "object") return null;
  if (seen.has(node)) return null;
  seen.add(node);

  if (Array.isArray(node)) {
    for (const item of node) {
      const found = findExternalRef(item, seen);
      if (found !== null) return found;
    }
    return null;
  }

  for (const [key, value] of Object.entries(node)) {
    if (key === "$ref" && typeof value === "string" && !value.startsWith("#/")) {
      return value;
    }
    const found = findExternalRef(value, seen);
    if (found !== null) return found;
  }
  return null;
}

// swagger-parser's own semantic pass never does this for OpenAPI 3.x
// (SEC-FE-001). Operations without an operationId are legal and are skipped.
function findDuplicateOperationId(api) {
  const seenIds = new Set();
  for (const pathItem of Object.values(api.paths || {})) {
    if (pathItem === null || typeof pathItem !== "object") continue;
    for (const [key, operation] of Object.entries(pathItem)) {
      if (!HTTP_METHODS.has(key.toLowerCase())) continue;
      if (operation === null || typeof operation !== "object") continue;
      const id = operation.operationId;
      if (typeof id !== "string" || id === "") continue;
      if (seenIds.has(id)) return id;
      seenIds.add(id);
    }
  }
  return null;
}

const specFile = process.argv[2];

if (!specFile) {
  console.error("INVALID: no spec file argument");
  process.exit(2);
}

if (!existsSync(specFile)) {
  console.error(`INVALID: spec file not found: ${specFile}`);
  process.exit(1);
}

const specBytes = statSync(specFile).size;
if (specBytes > MAX_SPEC_BYTES) {
  console.error(
    `INVALID: spec file too large: ${specBytes} bytes (limit ${MAX_SPEC_BYTES})`,
  );
  process.exit(1);
}

try {
  // Resolve internal $refs only. swagger-parser follows external http(s)/file
  // $refs by default, which would let a spec under test trigger a network fetch
  // or arbitrary file read in CI. All specs this validator sees are
  // self-contained (PR #187 review finding SEC-BE-001).
  const api = await SwaggerParser.validate(specFile, {
    resolve: { external: false },
  });

  const duplicateId = findDuplicateOperationId(api);
  if (duplicateId !== null) {
    console.error(`INVALID: duplicate operationId: ${duplicateId}`);
    process.exit(1);
  }

  // resolve.external:false stops the fetch/read, but it also means an
  // unresolvable external $ref stops being an error at all -- the document just
  // validates with the raw $ref left in place. Flag it explicitly (SEC-FE-002).
  // This must walk a NON-dereferenced copy: SwaggerParser.validate() inlines
  // internal $refs away in the object it returns, whereas parse() leaves every
  // original $ref string intact.
  const rawApi = await SwaggerParser.parse(specFile);
  const externalRef = findExternalRef(rawApi);
  if (externalRef !== null) {
    console.error(`INVALID: external $ref not permitted: ${externalRef}`);
    process.exit(1);
  }

  const pathCount = api.paths ? Object.keys(api.paths).length : 0;
  const version = api.openapi || api.swagger || "unknown";
  console.log(`OK: valid OpenAPI ${version} spec (${pathCount} paths)`);
  process.exit(0);
} catch (err) {
  // swagger-parser errors carry a multi-line message; keep the first line so
  // the shell log stays readable while still naming the offending field.
  const first = String(err && err.message ? err.message : err).split("\n")[0];
  console.error(`INVALID: ${first}`);
  process.exit(1);
}
