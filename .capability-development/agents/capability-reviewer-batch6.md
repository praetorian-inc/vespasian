# Review: Vespasian Batch 6 Implementation

**Reviewer:** capability-reviewer
**Date:** 2026-01-28
**Batch:** Batch 6 - Output and Integration (SDK Integration)

---

## Review Result
REVIEW_REJECTED

### Critical Issues

**Issue 1: Adapter Type Mismatch - CRITICAL**
- **Location:** `pkg/output/adapter.go:14-54`
- **Problem:** The plan specifies converting to `capability.Finding` (from capability-sdk), but the implementation uses `formatter.Finding` (from capability-sdk/pkg/formatter)
- **Expected:** `import "github.com/praetorian-inc/capability-sdk/pkg/capability"`
- **Actual:** `import "github.com/praetorian-inc/capability-sdk/pkg/formatter"`
- **Impact:** This is a fundamental contract violation. The plan (line 1686-1688) explicitly shows:
  ```go
  import (
      "github.com/praetorian-inc/capability-sdk/pkg/capability"
      "github.com/praetorian-inc/vespasian/pkg/probes"
  )
  func ToFindings(results []probes.ProbeResult) []capability.Finding
  ```
- **Action:** MUST change to use `capability.Finding` not `formatter.Finding`

**Issue 2: Missing Error Handling for Failed Probes - CRITICAL**
- **Location:** `pkg/output/adapter.go:18-21`
- **Problem:** Failed probes (Success=false) are silently skipped without any output
- **Plan Requirement:** Lines 1708-1717 show error findings must be created for failed probes
- **Expected Behavior:** Create a Finding with type=FindingAttribute for probe errors
- **Actual Behavior:** Skipped entirely with comment "// Skip failed probes"
- **Impact:** Users won't know which probes failed or why scans are incomplete
- **Action:** Implement error finding creation as specified in plan

**Issue 3: Incorrect Deduplication Key - HIGH**
- **Location:** `pkg/discovery/dedupe.go:54-55`
- **Problem:** Deduplication key format is `path:method` but review checklist specifies `method:path`
- **Specified:** "Deduplication uses correct key (method:path)"
- **Actual:** `strings.ToLower(endpoint.Path) + ":" + endpoint.Method`
- **Impact:** While functionally equivalent for uniqueness, violates explicit specification
- **Action:** Change to `endpoint.Method + ":" + strings.ToLower(endpoint.Path)`

---

## Plan Adherence

**Plan Location:** `/Users/nathansportsman/capabilities/modules/vespasian/.capability-development/plan.md` (lines 1568-1805)

| Plan Requirement | Status | Notes |
|------------------|--------|-------|
| Use capability-sdk for formatting | ⚠️ PARTIAL | Uses formatter sub-package, not capability package as specified |
| Adapter converts ProbeResult → capability.Finding | ❌ FAIL | Uses formatter.Finding instead of capability.Finding |
| 5 output formats working (Terminal, JSON, NDJSON, Markdown, SARIF) | ✅ PASS | All 5 formats tested and passing |
| End-to-end scan produces valid output | ✅ PASS | Integration test passes |
| All tests pass | ✅ PASS | 17 packages, all tests passing |
| Existing 112 tests remain passing | ✅ PASS | Verified with `go test ./... -v` |
| Writer wraps SDK formatter | ✅ PASS | Correct implementation in writer.go |
| Orchestrator sorts by priority | ✅ PASS | Implemented in orchestrator.go:74-84 |
| Orchestrator runs concurrently | ✅ PASS | Uses sync.WaitGroup correctly |
| Deduplication key format (method:path) | ❌ FAIL | Implemented as path:method |

### Deviations from Plan

1. **Package Import Mismatch**
   - **Deviation:** Uses `capability-sdk/pkg/formatter` instead of `capability-sdk/pkg/capability`
   - **Impact:** Type system violation - returns wrong type from ToFindings()
   - **Action:** MUST fix - change imports and types to match plan specification

2. **Failed Probe Handling**
   - **Deviation:** Skips failed probes instead of creating error findings
   - **Impact:** Loss of diagnostic information, incomplete scan visibility
   - **Action:** MUST fix - implement error finding creation per plan lines 1708-1717

3. **Deduplication Key Order**
   - **Deviation:** Uses `path:method` instead of specified `method:path`
   - **Impact:** Minor - functionally equivalent but violates spec
   - **Action:** Should fix for specification compliance

---

## Code Quality Issues

### Scanner Integration Standards

| Severity | Issue | Location | Action |
|----------|-------|----------|--------|
| CRITICAL | Type mismatch: formatter.Finding vs capability.Finding | adapter.go:14 | Change return type to []capability.Finding |
| CRITICAL | Failed probes not reported in output | adapter.go:18-21 | Create error findings for failures |
| HIGH | Deduplication key order incorrect | dedupe.go:54-55 | Change to method:path format |
| MEDIUM | Missing timeout documentation | orchestrator.go:49 | Document why 30s timeout is chosen |
| LOW | Magic number in timeout | orchestrator.go:49 | Consider making configurable |

### Design Quality Assessment

**Strengths:**
1. ✅ Clean adapter pattern separating concerns
2. ✅ Proper SDK formatter lifecycle (Initialize → Format → Complete)
3. ✅ Good test coverage: pkg/output 92.3%, pkg/discovery 100.0%
4. ✅ Concurrent probe execution with proper synchronization
5. ✅ Comprehensive integration tests covering all 5 output formats

**Weaknesses:**
1. ❌ Type system violation (wrong Finding type)
2. ❌ Silent failure handling (skipped errors)
3. ❌ Hardcoded timeout value
4. ⚠️ Deduplication key format mismatch

---

## Verification Results

**Go Compilation:**
```bash
$ go vet ./pkg/output/... ./pkg/discovery/...
✅ PASS - No vet warnings
```

**Build Verification:**
```bash
$ go build ./...
✅ PASS - Build succeeds
```

**Test Execution:**
```bash
$ go test ./... -v
✅ PASS - All 17 packages passing
- cmd/vespasian: PASS
- pkg/config: PASS (100.0% coverage)
- pkg/crawler: PASS (72.7% coverage)
- pkg/discovery: PASS (100.0% coverage)
- pkg/http: PASS (84.8% coverage)
- pkg/js: PASS (97.7% coverage)
- pkg/output: PASS (92.3% coverage)
- pkg/probes: PASS (100.0% coverage)
- pkg/protocols/grpc: PASS (25.7% coverage)
- pkg/protocols/websocket: PASS (80.6% coverage)
- pkg/registry: PASS (96.2% coverage)
- pkg/spec/graphql: PASS (79.5% coverage)
- pkg/spec/openapi: PASS (70.6% coverage)
- pkg/spec/wsdl: PASS (77.4% coverage)
- tests/integration: PASS
```

**Integration Tests:**
```bash
$ go test ./tests/integration/... -v
✅ PASS - All 7 integration tests passing:
- TestEndToEndScan: PASS (0.32s)
- TestOutputFormat_JSON: PASS
- TestOutputFormat_NDJSON: PASS
- TestOutputFormat_Terminal: PASS
- TestOutputFormat_Markdown: PASS
- TestOutputFormat_SARIF: PASS
- TestDeduplication_AcrossProbes: PASS
```

**Test Coverage:**
- pkg/output: 92.3% ✅
- pkg/discovery: 100.0% ✅
- Overall: High coverage across critical packages

---

## DRY Analysis

**Reviewed for code duplication:**

✅ **No significant duplication detected** in Batch 6 files:
- adapter.go: Single responsibility (conversion)
- writer.go: Single responsibility (output lifecycle)
- orchestrator.go: Single responsibility (coordination)
- dedupe.go: Single responsibility (deduplication)
- Integration tests: Appropriate test duplication for coverage

**Pattern reuse:**
- Correctly reuses capability-sdk formatter patterns
- Follows existing probe interface patterns
- Consistent error handling across discovery package

---

## Scope Compliance (YAGNI)

**Reviewed for scope creep:**

✅ **Implementation stays within Batch 6 scope:**
- Only implements specified adapter + writer
- No extra features beyond plan
- No premature abstractions
- Appropriate use of SDK formatters (5 formats as specified)

⚠️ **Minor concern:**
- sanitizePath() function in adapter.go lines 62-79 is more complex than plan suggested
- However, this is necessary for ID generation, not scope creep

---

## Cyclomatic Complexity

**Manual review (gocyclo not available):**

- `ToFindings()`: Low complexity (simple iteration)
- `WriteFindings()`: Low complexity (linear lifecycle)
- `Discover()`: Medium complexity (filtering + goroutines, appropriate for coordination)
- `DedupeEndpoints()`: Low complexity (single loop with map)
- `sanitizePath()`: Medium complexity (character iteration, acceptable for sanitization)

✅ **No functions exceed complexity threshold** - all appropriately structured

---

## Verdict

**CHANGES REQUESTED**

### Required Changes Before Approval

1. **Fix Type Mismatch (CRITICAL)**
   - Change `pkg/output/adapter.go` to import and use `capability.Finding` not `formatter.Finding`
   - Update function signature: `func ToFindings(results []probes.ProbeResult) []capability.Finding`
   - Verify capability-sdk exports Finding type from capability package

2. **Implement Error Handling (CRITICAL)**
   - Remove line 18-21 "skip failed probes" logic
   - Add error finding creation for failed probes per plan lines 1708-1717:
     ```go
     if pr.Error != nil && !pr.Success {
         f := capability.Finding{
             Type:     capability.FindingAttribute,
             Severity: capability.SeverityInfo,
             Data: map[string]any{
                 "type":           "probe_error",
                 "probe_category": pr.ProbeCategory.String(),
                 "error":          pr.Error.Error(),
             },
         }
         findings = append(findings, f)
     }
     ```

3. **Fix Deduplication Key (HIGH)**
   - Change `pkg/discovery/dedupe.go` line 55 from:
     ```go
     return strings.ToLower(endpoint.Path) + ":" + endpoint.Method
     ```
   - To:
     ```go
     return endpoint.Method + ":" + strings.ToLower(endpoint.Path)
     ```

### Recommended Improvements (Not Blocking)

1. Document timeout rationale in orchestrator.go line 49
2. Consider making timeout configurable via ProbeOptions

### Testing Required After Changes

After implementing fixes:
1. Run full test suite: `go test ./... -v`
2. Verify integration tests still pass: `go test ./tests/integration/... -v`
3. Manually verify error finding creation with failing probe
4. Verify deduplication key change doesn't break existing behavior

---

## Summary

The Batch 6 implementation demonstrates good architectural design and comprehensive testing. However, it contains **three critical deviations** from the approved plan:

1. **Type system violation** - uses wrong Finding type from SDK
2. **Missing error handling** - silently drops failed probe results
3. **Specification mismatch** - deduplication key format incorrect

The code builds, tests pass, and output formatting works correctly for successful probes. But the type mismatch and missing error handling are **blocking issues** that must be fixed before approval.

**Estimated fix time:** 15-20 minutes for all three issues

**Recommendation:** Return to capability-developer for fixes, then re-review.

---

## Metadata

```json
{
  "agent": "capability-reviewer",
  "output_type": "code-review",
  "timestamp": "2026-01-28T23:55:19Z",
  "feature_directory": "/Users/nathansportsman/capabilities/modules/vespasian/.capability-development",
  "skills_invoked": [
    "using-skills",
    "adhering-to-dry",
    "adhering-to-yagni",
    "analyzing-cyclomatic-complexity",
    "calibrating-time-estimates",
    "discovering-reusable-code",
    "debugging-systematically",
    "enforcing-evidence-based-analysis",
    "gateway-backend",
    "gateway-capabilities",
    "persisting-agent-outputs",
    "verifying-before-completion",
    "using-todowrite",
    "reviewing-capability-implementations"
  ],
  "library_skills_read": [
    ".claude/skill-library/development/capabilities/reviewing-capability-implementations/SKILL.md"
  ],
  "source_files_verified": [
    "/Users/nathansportsman/capabilities/modules/vespasian/pkg/output/adapter.go:1-80",
    "/Users/nathansportsman/capabilities/modules/vespasian/pkg/output/writer.go:1-91",
    "/Users/nathansportsman/capabilities/modules/vespasian/pkg/discovery/orchestrator.go:1-85",
    "/Users/nathansportsman/capabilities/modules/vespasian/pkg/discovery/dedupe.go:1-57",
    "/Users/nathansportsman/capabilities/modules/vespasian/tests/integration/scan_test.go:1-338",
    "/Users/nathansportsman/capabilities/modules/vespasian/.capability-development/plan.md:1568-1718"
  ],
  "verification_commands_run": [
    "go vet ./pkg/output/... ./pkg/discovery/...",
    "go test ./tests/integration/... -v",
    "go test ./... -v",
    "go build ./...",
    "go test ./... -cover"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": "capability-developer",
    "context": "Fix 3 issues: (1) Change adapter.go to use capability.Finding not formatter.Finding, (2) Implement error finding creation for failed probes, (3) Fix deduplication key to method:path format. Then re-run tests and request re-review."
  }
}
```
