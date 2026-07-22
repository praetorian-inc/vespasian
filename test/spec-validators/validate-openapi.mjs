#!/usr/bin/env node
// Copyright 2026 Praetorian Security, Inc.
//
// Real OpenAPI validator for the vespasian live-test suite (LAB-3890 T1).
// Replaces the old grep-for-top-level-keys check, which passed any file that
// merely contained the strings "openapi:", "info:" and "paths:" on a line.
//
// Uses @apidevtools/swagger-parser, which validates the document against the
// OpenAPI 2.0/3.0 JSON schema AND performs semantic checks a spec *generator*
// can realistically break: unresolved $refs and duplicate operationIds. YAML
// and JSON are both accepted. Fully offline once `npm ci` has run.
//
// Usage:   node validate-openapi.mjs <spec_file>
// Exit 0 + "OK: ..." on a valid spec; exit 1 + "INVALID: <reason>" otherwise.

import { existsSync } from "node:fs";
import SwaggerParser from "@apidevtools/swagger-parser";

const specFile = process.argv[2];

if (!specFile) {
  console.error("INVALID: no spec file argument");
  process.exit(2);
}

if (!existsSync(specFile)) {
  console.error(`INVALID: spec file not found: ${specFile}`);
  process.exit(1);
}

try {
  const api = await SwaggerParser.validate(specFile);
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
