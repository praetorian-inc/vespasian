// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crawl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"
)

// checkpointVersion is the on-disk schema version. Load rejects a checkpoint
// written by a different version so a format change cannot be misread as valid
// resume state.
const checkpointVersion = 1

// DefaultCheckpointMaxAge bounds how old a checkpoint may be and still be reused.
// It is sized to Guard's crawl cadence (~5 days): coverage accumulates across a
// cycle, but a checkpoint older than this is discarded so the crawl does not
// resume from arbitrarily stale state (LAB-4678 Phase 4).
const DefaultCheckpointMaxAge = 5 * 24 * time.Hour

// Checkpoint is the cross-run resume state produced at the end of a (possibly
// truncated) crawl and consumed at the start of the next. It carries the pages
// still queued but not yet visited (Pending) so a resumed run continues the
// unvisited frontier instead of restarting, and the full set of URL keys already
// enqueued (Seen) so neither the resumed frontier nor newly-discovered links
// re-crawl covered pages. It is gated by ConfigFingerprint (a different crawl
// config invalidates it) and CreatedAtUnix (staleness).
//
// Storing and passing the checkpoint between runs is the caller's concern (for
// Guard, a platform piece coordinated separately); vespasian only produces,
// serializes, validates, and consumes it.
//
// LIFECYCLE: Seen is cumulative, not per-run. Restore seeds it and Snapshot
// writes it back, so it grows monotonically across every resume cycle — that
// accumulation is what makes coverage carry forward, and nothing here prunes it.
// The host owns that lifecycle: it must reset or prune periodically, because a
// Seen set that grows past MaxCheckpointEntries makes the artifact permanently
// unloadable by LoadCheckpoint and resume degrades to a full re-crawl. Producing
// a checkpoint is deliberately not bounded — silently dropping seen keys at write
// time would re-crawl covered pages with no signal, which is worse than a loud
// failure at read time.
type Checkpoint struct {
	Version           int          `json:"version"`
	ConfigFingerprint string       `json:"config_fingerprint"`
	CreatedAtUnix     int64        `json:"created_at_unix"`
	Pending           []PendingURL `json:"pending"`
	Seen              []string     `json:"seen"`
}

// PendingURL is one queued-but-unvisited page carried by [Checkpoint.Pending]: a
// URL and the crawl depth it was discovered at.
//
// It is exported because Phase 4's premise is that the HOST owns checkpoint
// storage and hand-back. With an unexported element type, an external consumer
// could round-trip a checkpoint as opaque JSON but could not construct one with
// pending entries or handle them in a typed way, which blocks the intended
// consumer.
//
// The JSON tags are the field names Go would have used for the previously
// untagged struct, so the on-disk format is unchanged and a checkpoint written
// before this type was exported still loads.
type PendingURL struct {
	URL   string `json:"URL"`
	Depth int    `json:"Depth"`
}

// ComputeConfigFingerprint returns a stable hash of the crawl-defining inputs.
// A resumed run may only reuse a checkpoint whose fingerprint matches, so a
// change to the target, scope, or depth (which would change what the crawl
// covers) invalidates prior state rather than silently accumulating coverage
// across incompatible configs. MaxPages/MaxRequests are intentionally excluded:
// they bound a single run's budget, not what the crawl is allowed to cover, so a
// larger budget on resume should continue the same coverage, not invalidate it.
//
// headless is included because the two backends do not discover the same link
// set: the headless engine executes JavaScript and captures every subresource
// request, while the net/http backend records one request per page and sees only
// links present in the served HTML. Resuming a headless checkpoint on the
// net/http backend would mark JS-discovered pages as already covered and skip
// them, permanently losing that surface — so a backend change invalidates the
// checkpoint just like a scope change.
//
// allowPrivate is included because it changes what the crawl is PERMITTED to
// reach, not merely how much of it. A checkpoint recorded with private targets
// allowed carries pending URLs and covered keys that the stricter config would
// never have produced, so reusing it across that boundary is a policy change,
// not resumed coverage. [urlFrontier.Restore] independently re-validates every
// restored pending URL against the current scope predicate; this is the second
// layer, so the two must both fail before a checkpoint can widen the crawl's
// reach (Codex review, PR #189).
//
// interact is included for the same reason as headless: it changes WHAT the crawl
// discovers, not how much. --interact clicks controls to surface endpoints that a
// passive visit never fires, so a page covered without it is not covered with it.
// Omitting it meant enabling --interact on a resumed run produced ZERO extra
// coverage — Restore marks every previously-visited page seen, and the interaction
// pass only runs on pages the crawl visits. If the prior run drained the frontier
// the follow-up did not merely under-cover, it failed outright with "nothing to
// crawl" (LAB-4678 review, SEC-BE-001).
//
// MEMBERSHIP RULE, so the next option is not forgotten the same way: an input
// belongs here when changing it changes the set of URLs or requests the crawl can
// discover or is permitted to reach. It does NOT belong here when it only bounds
// how much of that set one run gets through. Apply this test before adding a
// CrawlerOptions field, and see TestComputeConfigFingerprint_CoversEveryParameter
// for the guard that every parameter here actually affects the hash.
//
// Headers are deliberately EXCLUDED, which is the one case where the rule above
// does not settle it. Credentials do change the reachable surface, so by the rule
// they would belong. They are excluded anyway because the common operator action is
// re-supplying a REFRESHED token for the same identity, and invalidating the
// checkpoint on every token rotation would make resume unusable for exactly the
// authenticated crawls it is most valuable for. The cost is real and is the
// operator's to manage: a crawl first run unauthenticated, then resumed with
// -H "Authorization: ...", permanently skips the authenticated surface behind
// already-seen pages, because Seen accumulates and nothing prunes it. Start a fresh
// checkpoint when the identity changes rather than the token.
func ComputeConfigFingerprint(targetURL, scope string, depth int, headless, allowPrivate, interact bool) string {
	// Length-prefix each field so ("a","b") and ("ab","") cannot collide, then
	// hash the assembled input in one shot.
	field := func(s string) string { return strconv.Itoa(len(s)) + ":" + s }
	input := field(targetURL) + field(scope) + field(strconv.Itoa(depth)) +
		field(strconv.FormatBool(headless)) + field(strconv.FormatBool(allowPrivate)) +
		field(strconv.FormatBool(interact))
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// resumeOptions carries the cross-run resume wiring shared by both crawl
// backends. Fingerprint identifies the current crawl config (see
// [ComputeConfigFingerprint]); MaxAge bounds checkpoint staleness, with a
// non-positive value falling back to [DefaultCheckpointMaxAge].
type resumeOptions struct {
	From        *Checkpoint
	On          func(*Checkpoint)
	Fingerprint string
	MaxAge      time.Duration
}

// maxAgeOrDefault resolves the staleness bound, treating a non-positive
// configured value as "use the default" rather than "disable the check", so a
// caller that leaves the field unset still gets staleness protection.
func (r resumeOptions) maxAgeOrDefault() time.Duration {
	if r.MaxAge <= 0 {
		return DefaultCheckpointMaxAge
	}
	return r.MaxAge
}

// resumeFrontier applies r.From to f when that checkpoint is usable for the
// current config, and reports whether it resumed. An absent checkpoint is not an
// error (a fresh crawl), and an unusable one is a warning rather than a failure:
// a stale or mismatched checkpoint should degrade to a full crawl, not abort it.
// Both outcomes are announced on stderr so an operator can tell a resumed run
// from a fresh one instead of silently getting different coverage.
func resumeFrontier(f *urlFrontier, r resumeOptions, now time.Time, stderr io.Writer) bool {
	if r.From == nil {
		return false
	}
	if ok, why := r.From.Usable(r.Fingerprint, now, r.maxAgeOrDefault()); !ok {
		if stderr != nil {
			fmt.Fprintf(stderr, "resume: ignoring checkpoint (%s); starting a fresh crawl\n", why) //nolint:errcheck // best-effort status
		}
		return false
	}
	f.Restore(r.From.Pending, r.From.Seen)
	if stderr != nil {
		fmt.Fprintf(stderr, "resume: restored %d pending pages, %d URLs already covered\n", //nolint:errcheck // best-effort status
			len(r.From.Pending), len(r.From.Seen))
	}
	return true
}

// captureCheckpoint snapshots f as a Checkpoint stamped with the current config
// fingerprint and now, then hands it to r.On. It is a no-op without a callback.
// Called after the crawl's workers have stopped, on every exit path including
// budget truncation and cancellation — truncation is precisely the case resume
// exists to carry forward.
func captureCheckpoint(f *urlFrontier, r resumeOptions, now time.Time) {
	if r.On == nil {
		return
	}
	pending, seen := f.Snapshot()
	r.On(&Checkpoint{
		Version:           checkpointVersion,
		ConfigFingerprint: r.Fingerprint,
		CreatedAtUnix:     now.Unix(),
		Pending:           pending,
		Seen:              seen,
	})
}

// Save writes the checkpoint as JSON to w.
func (c *Checkpoint) Save(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encode checkpoint: %w", err)
	}
	return nil
}

// Layered bounds on a decoded checkpoint. A checkpoint is read back from host
// storage rather than produced in-process, so it is parsed input and gets the
// same treatment as the importers: a byte cap on the reader and an element cap on
// each slice.
//
// BOTH caps are load-bearing, and that took a fix. The element caps used to be
// checked with len() AFTER json.Unmarshal had already materialized the whole
// decoded value, so only MaxCheckpointBytes actually bounded anything and the
// comment here claimed more than the code delivered (LAB-4678 review, SEC-BE-002).
// The caps are now enforced DURING decode by boundedPending and boundedSeen.
//
// Measured against this code, peak RSS in a separate process, rejecting a 64 MB
// artifact made of 16.7M one-character seen keys:
//
//	before: 1265 MB    after: 196 MB
//
// For reference a LEGITIMATE checkpoint at exactly MaxCheckpointEntries (1M
// realistic URL keys) is 51.4 MB on disk and costs 229 MB to decode, and is
// accepted. So the adversarial worst case now costs no more than the legitimate
// worst case, which is the property worth having: an attacker cannot make rejection
// more expensive than ordinary use.
//
// That 51.4 MB figure is also why MaxCheckpointBytes was NOT simply lowered
// instead, which was the other option considered. Bounding transient memory to
// ~230 MB through the byte cap alone needs a cap around 12 MB, which caps a
// legitimate checkpoint at roughly 230k entries and makes the documented 1M entry
// cap unreachable — the byte cap would silently become the real limit while the
// entry cap kept claiming otherwise. The ~20x expansion is specific to the
// adversarial shape, where tiny elements maximize per-string overhead; realistic
// URLs expand about 4x. So the defense has to target element COUNT, which is what
// the entry cap always claimed to do and now actually does.
const (
	// MaxCheckpointBytes bounds the encoded size accepted by LoadCheckpoint.
	MaxCheckpointBytes = 64 * 1024 * 1024 // 64 MB
	// MaxCheckpointEntries bounds Pending and Seen independently, enforced during
	// decode rather than after it; see boundedPending and boundedSeen.
	MaxCheckpointEntries = 1_000_000
)

// boundedPending and boundedSeen are [Checkpoint.Pending] and [Checkpoint.Seen]
// during decoding only. Each stops at MaxCheckpointEntries and errors instead of
// decoding the rest of the array, which is what keeps a hostile artifact from
// costing 1.3 GB of transient allocation to reject.
//
// They exist as separate types, rather than as a hand-rolled token loop over the
// whole object, so encoding/json still drives the object structure. A hand-written
// parser on a parsed-input security boundary is where bugs live, and the existing
// read-then-unmarshal shape also keeps the byte-cap check exact: a decoder streaming
// straight off the reader would have consumed a prefix before the overflow was
// detectable, turning "checkpoint exceeds N bytes" into a JSON syntax error.
type (
	boundedPending []PendingURL
	boundedSeen    []string
)

// UnmarshalJSON decodes the pending array, refusing more than MaxCheckpointEntries.
func (b *boundedPending) UnmarshalJSON(data []byte) error {
	return decodeBoundedArray(data, "pending", MaxCheckpointEntries, func(dec *json.Decoder) error {
		var e PendingURL
		if err := dec.Decode(&e); err != nil {
			return err
		}
		*b = append(*b, e)
		return nil
	})
}

// UnmarshalJSON decodes the seen array, refusing more than MaxCheckpointEntries.
func (b *boundedSeen) UnmarshalJSON(data []byte) error {
	return decodeBoundedArray(data, "seen", MaxCheckpointEntries, func(dec *json.Decoder) error {
		var s string
		if err := dec.Decode(&s); err != nil {
			return err
		}
		*b = append(*b, s)
		return nil
	})
}

// decodeBoundedArray token-decodes a JSON array from data, calling decodeElem for
// each element and aborting once max is passed. name appears in the error so the
// operator learns WHICH array overflowed, matching the diagnostic the previous
// post-decode len() checks produced.
//
// max is a parameter rather than a direct read of MaxCheckpointEntries so the abort
// semantics are testable at a small bound. Proving early abort otherwise requires
// building a payload past the real 1,000,000-element cap, which costs seconds per
// case and would roughly double this package's test time for behavior that is
// independent of the constant's value.
func decodeBoundedArray(data []byte, name string, max int, decodeElem func(*json.Decoder) error) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	// A JSON null for the field is valid and means "absent", matching how
	// encoding/json treats a null slice.
	if tok == nil {
		return nil
	}
	if tok != json.Delim('[') {
		return fmt.Errorf("checkpoint %s: expected an array", name)
	}
	n := 0
	for dec.More() {
		n++
		if n > max {
			return fmt.Errorf("checkpoint %s entries exceed %d", name, max)
		}
		if err := decodeElem(dec); err != nil {
			return err
		}
	}
	// Closing bracket.
	_, err = dec.Token()
	return err
}

// UnmarshalJSON decodes a checkpoint with the two unbounded arrays capped during
// decode. Every other field is decoded by encoding/json through the embedded alias,
// so a field added to Checkpoint is picked up here with no change and this cannot
// drift out of sync with the struct.
//
// The alias is a defined type rather than a type alias, which strips the method set
// and stops this method from recursing into itself.
func (c *Checkpoint) UnmarshalJSON(data []byte) error {
	type alias Checkpoint
	var wire struct {
		alias
		// Shadow the two array fields at depth 0, so encoding/json prefers these
		// over the embedded alias's copies.
		Pending boundedPending `json:"pending"`
		Seen    boundedSeen    `json:"seen"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*c = Checkpoint(wire.alias)
	c.Pending = wire.Pending
	c.Seen = wire.Seen
	return nil
}

// LoadCheckpoint decodes a checkpoint from r and rejects an unknown schema
// version, so a format change fails closed rather than being misinterpreted. The
// reader is capped at MaxCheckpointBytes and each slice at MaxCheckpointEntries;
// exceeding either is an error rather than a silent truncation, since a truncated
// seen-set would let the resumed crawl re-cover pages it should skip.
//
// The element caps are enforced inside [Checkpoint.UnmarshalJSON] rather than by a
// len() check here. A post-decode check cannot bound anything: by the time it runs,
// the oversized array has already been materialized, which is the whole cost being
// defended against. There is deliberately no len() re-check below — a successful
// decode has already rejected an over-cap array, so the re-check would never fire,
// and validation that never fires reads as protection that is not there.
// TestBoundedDecodersUseTheRealCap and TestLoadCheckpoint_RealCapIsEnforcedEndToEnd
// pin that the decode path is what enforces it.
func LoadCheckpoint(r io.Reader) (*Checkpoint, error) {
	// Read under the cap first (+1 so a payload exactly at the cap is
	// distinguishable from one over it), then unmarshal. Reading before decoding
	// keeps the size check exact and unambiguous: a streaming decoder would have
	// already consumed a prefix by the time the overflow is detectable.
	data, err := io.ReadAll(io.LimitReader(r, MaxCheckpointBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read checkpoint: %w", err)
	}
	if len(data) > MaxCheckpointBytes {
		return nil, fmt.Errorf("checkpoint exceeds %d bytes", MaxCheckpointBytes)
	}
	var c Checkpoint
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("decode checkpoint: %w", err)
	}
	if c.Version != checkpointVersion {
		return nil, fmt.Errorf("checkpoint version %d unsupported (want %d)", c.Version, checkpointVersion)
	}
	return &c, nil
}

// Usable reports whether the checkpoint may be reused for a crawl with the given
// fingerprint as of now, and a human-readable reason when it may not. A
// mismatched config fingerprint or an age exceeding maxAge (measured from
// CreatedAtUnix) makes it unusable. A non-positive maxAge disables the staleness
// check (age is not considered).
func (c *Checkpoint) Usable(fingerprint string, now time.Time, maxAge time.Duration) (bool, string) {
	if c.Version != checkpointVersion {
		return false, fmt.Sprintf("version %d unsupported", c.Version)
	}
	if c.ConfigFingerprint != fingerprint {
		return false, "config fingerprint mismatch (target/scope/depth changed)"
	}
	if maxAge > 0 {
		age := now.Sub(time.Unix(c.CreatedAtUnix, 0))
		if age > maxAge {
			return false, fmt.Sprintf("checkpoint is stale (age %s > max %s)", age.Truncate(time.Second), maxAge)
		}
		if age < 0 {
			return false, "checkpoint timestamp is in the future"
		}
	}
	return true, ""
}

// Snapshot captures the frontier's current pending queue and seen-set as a
// deterministic, resumable state. The seen keys are sorted so the serialized
// checkpoint is byte-stable for a given frontier state. Safe to call after the
// crawl's workers have stopped.
//
// Pages recorded by [urlFrontier.MarkFailed] are OMITTED from seen: they were
// attempted and failed transiently, and because seen accumulates across every
// resume cycle, persisting them would make a one-off failure a permanent drop.
// Omitting them costs nothing on a fresh crawl and gives the next resumed run one
// more attempt at the page.
func (f *urlFrontier) Snapshot() (pending []PendingURL, seen []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pending = make([]PendingURL, len(f.queue))
	copy(pending, f.queue)

	// Transiently-failed pages go back on the PENDING queue, not merely out of
	// seen. They were popped before failing, so they are in neither the queue nor
	// (once excluded below) the seen-set; carrying them in neither half would
	// drop them from resume entirely, and they would be retried only if some
	// other pending page happened to re-link them. A run whose only failure was
	// the last page would resume with an empty queue and a complete seen-set,
	// report "nothing to crawl", and never revisit it.
	//
	// Sorted before appending because f.failed is a map: unsorted iteration would
	// make the checkpoint's pending order vary run to run for identical input,
	// which is the determinism this ticket exists to remove.
	failedKeys := make([]string, 0, len(f.failed))
	for k := range f.failed {
		failedKeys = append(failedKeys, k)
	}
	sort.Strings(failedKeys)
	for _, k := range failedKeys {
		pending = append(pending, f.failed[k])
	}

	seen = make([]string, 0, len(f.seen))
	for k := range f.seen {
		if _, isFailed := f.failed[k]; isFailed {
			continue
		}
		seen = append(seen, k)
	}
	sort.Strings(seen)
	return pending, seen
}

// Restore pre-loads resume state into the frontier before the crawl starts: the
// seen keys are marked so neither the restored queue nor newly-discovered links
// re-enqueue a covered page, and the pending entries are placed on the queue.
// Call on a fresh frontier before seeding.
//
// Pending entries are re-validated against depth and scope even though they
// passed those checks in the run that produced them. A checkpoint is not
// in-process state: it round-trips through host storage, so it is parsed input,
// and [ComputeConfigFingerprint] cannot authenticate it — the fingerprint is
// derived from the crawl config, which is not secret, so anyone who can write to
// checkpoint storage can produce one that verifies. Appending Pending unchecked
// would let such an artifact seed the frontier with out-of-scope or private-network
// URLs, bypassing the scope and SSRF gates that [urlFrontier.Push] applies to
// every other URL. Re-checking here costs one predicate call per entry and makes
// the frontier's invariants hold regardless of where the queue came from.
//
// The seen check that Push applies is deliberately NOT applied: restored pending
// entries are legitimately in the checkpoint's seen-set already, and rejecting
// them on that basis would discard the entire resumed queue. They are marked seen
// here so a later rediscovery still dedups against them.
//
// Validation runs in two passes, BEFORE the lock is taken and then under it. The
// scope predicate performs a blocking DNS resolution (isPrivateHost) that takes no
// context, and LoadCheckpoint admits up to MaxCheckpointEntries pending entries,
// so calling it inside the critical section held f.mu across an unbounded amount
// of network I/O and blocked every concurrent frontier operation for the duration
// (LAB-4678 review, SEC-BE-003). The predicate is a pure function of the URL, so
// hoisting it out changes no verdict. Duplicate collapse still happens under the
// lock, because it is the frontier's own state that decides it.
func (f *urlFrontier) Restore(pending []urlEntry, seen []string) {
	// Pass 1, no lock held: the URL-only checks, including the one that resolves DNS.
	f.mu.Lock()
	maxDepth, scopeFn := f.maxDepth, f.scopeFn
	f.mu.Unlock()

	admitted := make([]urlEntry, 0, len(pending))
	for _, e := range pending {
		if seenKey(e.URL) == "" {
			continue
		}
		if maxDepth >= 0 && e.Depth > maxDepth {
			continue
		}
		if scopeFn != nil && !scopeFn(e.URL) {
			continue
		}
		admitted = append(admitted, e)
	}

	// Pass 2, under the lock: frontier state only.
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range admitted {
		key := seenKey(e.URL)
		// Dedup WITHIN pending. Restore runs on a fresh frontier, so anything
		// already in f.seen here was put there by an earlier entry of this same
		// slice — a corrupted or hand-edited checkpoint listing one URL repeatedly
		// would otherwise queue it once per occurrence and spend the page budget
		// refetching it (CodeRabbit review, PR #189). The checkpoint's own seen-set
		// is still applied after this loop, so it cannot reject the resumed queue.
		if f.seen[key] {
			continue
		}
		// Apply the same per-path query-variant cap Push applies. A checkpoint is
		// parsed input from host storage, so without this an artifact listing
		// MaxCheckpointEntries variants of one path would queue all of them and
		// spend the whole page budget on one page — a bound Push enforces on
		// discovered links but Restore would otherwise skip.
		pathKey := frontierKey(e.URL)
		if f.variants[pathKey] >= maxQueryVariantsPerPath {
			continue
		}
		f.seen[key] = true
		f.variants[pathKey]++
		f.queue = append(f.queue, e)
	}
	for _, k := range seen {
		f.seen[k] = true
	}
}
