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
	"context"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// maxInteractionsPerPage bounds how many click ATTEMPTS the interaction pass makes
// on a single page, so a page with hundreds of buttons cannot blow the page budget
// or hang the crawl. An attempt that is abandoned (unreadable label, failed click)
// still consumes one, which keeps the bound a hard cap on work done per page rather
// than on successful clicks. Interaction is opt-in (engineOptions.Interact) and off
// by default (LAB-4678 Phase 2).
const maxInteractionsPerPage = 8

// maxInteractionCandidates bounds how many matched elements collectInteractionElements
// will accumulate in one scan. maxInteractionsPerPage bounds the CLICKS; without this
// the CANDIDATE LIST was unbounded and driven entirely by page content: a page
// rendering 200,000 <button> nodes forced a CDP response carrying that many remote
// object IDs plus an equally sized rod.Elements and []string, re-collected before
// every click, across Concurrency tabs (LAB-4678 review, SEC-BE-007).
//
// The scan returns at the FIRST acceptable element, so truncating costs no realistic
// coverage: reaching this cap means several hundred candidates were all rejected as
// blank, destructive, or already clicked, and the pass has at most 8 clicks to spend
// regardless. Set well above maxInteractionsPerPage so ordinary pages never truncate.
const maxInteractionCandidates = 512

// interactionSelectors are the DOM selectors for elements likely to trigger
// client-side behavior (XHR/fetch or a client-side route change) when clicked,
// without a full navigation. Anchors are excluded: their hrefs are already
// discovered by extractLinks and pushed to the frontier.
var interactionSelectors = []string{
	"button",
	"[role=button]",
	"[onclick]",
}

// The destructive-label lists mark a control as
// likely destructive, session-ending, or an irreversible commit. The interaction
// pass skips these so a click does not delete data, drop the crawl's
// authenticated session, or spend money. The list is deliberately conservative —
// false negatives (a destructive control with an unusual label) are possible, so
// interaction stays opt-in.
//
// COVERAGE VS SAFETY. The list intentionally does NOT contain the generic
// state-mutating verbs (submit, save, send, apply, search, update, create). That
// is a considered tradeoff, not an omission: those labels sit on the controls that
// actually reveal API surface — a form's submit button is usually the ONLY way to
// observe its endpoint, method, and parameters — so skipping them would remove
// most of what --interact exists to find, and the endpoints they hit are the same
// ones a form-submission crawl would reach anyway. What IS listed are the actions
// whose consequences cannot be undone by re-running the crawl: data destruction,
// losing the session, and financial commits. For those the coverage is never worth
// the risk. Operators are told plainly in the README that --interact submits forms
// and mutates state, since no label list can make clicking safe.
// destructiveLabelWords are single words that mark a control as destructive when
// they appear as a WHOLE WORD in its label. Whole-word matching matters: a plain
// substring test made "drop" match "Dropdown", "pay" match "Payment history",
// "reset" match "Preset filters", and "wipe" match "Swipe" — all ordinary
// navigation and filter controls, silently removed from the interaction pass
// (CodeRabbit review, PR #189). Skipping a safe control is not free: it is
// exactly the surface --interact exists to reach.
var destructiveLabelWords = []string{
	"delete", "remove", "destroy", "drop",
	"logout", "signout",
	"deactivate", "deregister", "unsubscribe",
	"reset", "wipe", "revoke", "purge",
	// Unambiguous destructive verbs. Bare "cancel" is deliberately NOT here: a
	// dialog's Cancel button is safe and skipping it would lose real surface.
	"trash", "discard", "erase", "terminate", "archive",
	// Irreversible financial commits. A crawl that places an order or moves money
	// cannot undo it, so these are skipped even though they are ordinary form
	// submissions that would otherwise reveal endpoints.
	// "payment"/"payments" are listed alongside "pay" because whole-word matching
	// no longer reaches them through "pay", and "Submit payment" is exactly the
	// control that must never be clicked. This deliberately also skips a read-only
	// "Payment history" link: for irreversible financial actions the asymmetry is
	// not close, so the false positive is accepted where "Dropdown" was not.
	"pay", "payment", "payments", "purchase", "checkout", "withdraw",
}

// destructiveLabelPhrases are multi-word markers matched as substrings. A phrase
// is specific enough that a substring test cannot collide the way a bare word can.
var destructiveLabelPhrases = []string{
	"log out", "sign out", "cancel subscription", "clear all",
	"close account", "buy now", "place order", "check out",
	"transfer funds", "send money",
}

// labelAttributes are attributes that carry a control's accessible or fallback
// label. An icon-only or symbol control ("x", an SVG glyph) has no meaningful
// text node, so its actual meaning lives here — and a destructive action has to
// be recognizable from any of them, not from visible text alone.
//
// That assumption used to be unenforced in the one case it names. el.Text() returns
// DESCENDANT text, so <button>✕</button> or a private-use-area icon-font codepoint
// read back NON-BLANK, elementLabel reported ok=true, and isDestructiveLabel found
// nothing because it splits on letters and digits and a glyph is neither. The
// fail-closed layer was therefore unreachable for exactly the control shape this
// comment describes. labelIsReadable now decides readability on words rather than on
// non-emptiness, so a glyph-only label routes into the skip path
// (LAB-4678 review, SEC-BE-006).
var labelAttributes = []string{"aria-label", "title", "value"}

// descendantLabelAttributes are read from a control's DESCENDANTS, not the element
// itself. el.Attribute() does not descend, so <button><span title="Delete account">🗑
// </span></button> presented a glyph as its whole label and hid the meaning from both
// gates. alt is included for the <img> form of the same pattern.
var descendantLabelAttributes = []string{"aria-label", "title", "alt"}

// elementLabel returns everything that describes a control: its visible text
// plus every label-bearing attribute, joined so isDestructiveLabel matches a
// destructive verb wherever it appears.
//
// ok reports whether the label was fully READ, and is false when any read failed
// (a stale handle, a detached node, an eval error) or when the assembled label is not
// readable in the labelIsReadable sense — blank, or glyphs with no word in them. A
// caller must not treat a label it could not read as safe: the whole point of reading
// the label is to recognize a destructive control, so an unreadable one carries no
// evidence either way. See [clickAllowed].
func elementLabel(el *rod.Element) (label string, ok bool) {
	var parts []string
	txt, err := el.Text()
	if err != nil {
		return "", false
	}
	if strings.TrimSpace(txt) != "" {
		parts = append(parts, txt)
	}
	for _, attr := range labelAttributes {
		v, err := el.Attribute(attr)
		if err != nil {
			return "", false
		}
		if v != nil && strings.TrimSpace(*v) != "" {
			parts = append(parts, *v)
		}
	}
	desc, err := descendantLabelText(el)
	if err != nil {
		return "", false
	}
	if desc != "" {
		parts = append(parts, desc)
	}
	label = strings.Join(parts, " ")
	return label, labelIsReadable(label)
}

// descendantLabelText returns the descendantLabelAttributes found anywhere beneath el,
// space-joined. It exists because el.Attribute() reads only the matched element, so an
// icon wrapped in a labeled span or img kept its meaning out of both gates.
//
// One Eval for the whole subtree, matching the cost of the three Attribute round trips
// above. An Eval error is returned rather than swallowed so elementLabel fails closed:
// a label that could not be fully read is not evidence a control is safe.
func descendantLabelText(el *rod.Element) (string, error) {
	obj, err := el.Eval(`(attrs) => {
		const out = [];
		for (const node of this.querySelectorAll('*')) {
			for (const a of attrs) {
				const v = node.getAttribute(a);
				if (v && v.trim()) out.push(v.trim());
			}
		}
		return out.join(' ');
	}`, descendantLabelAttributes)
	if err != nil {
		return "", err
	}
	if obj == nil {
		return "", nil
	}
	return strings.TrimSpace(obj.Value.String()), nil
}

// labelWords splits a label into the words isDestructiveLabel matches against:
// every run of letters and digits, so punctuation and separators delimit a word and
// "Delete?" and "delete/remove" both yield "delete".
func labelWords(label string) []string {
	return strings.FieldsFunc(strings.ToLower(strings.TrimSpace(label)), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// labelIsReadable reports whether a label carries anything the destructive-label match
// can act on. A label of glyphs alone ("✕", 🗑, an icon-font codepoint) is NOT readable:
// it is non-empty, so a blank test passes it, but it yields zero words, so no word list
// can ever reject it. Treating it as read is what let the fail-closed gate permit a
// control it had no evidence about (LAB-4678 review, SEC-BE-006).
func labelIsReadable(label string) bool {
	return len(labelWords(label)) > 0
}

// clickAllowed is the pre-click decision: may the interaction pass click a control
// whose label read back as (label, ok)?
//
// It FAILS CLOSED. An unreadable or blank label (ok == false) is a skip, not a
// permit. The previous form tested only isDestructiveLabel(label), and
// elementLabel returned "" on a read failure, so isDestructiveLabel("") == false
// let the click proceed — precisely in the mid-re-render case the pre-click
// re-check exists to catch, and in disagreement with nextInteractionTarget,
// which skips unreadable labels up front. The two gates now agree in the
// restrictive direction.
func clickAllowed(label string, ok bool) bool {
	// The readability check is redundant with elementLabel's own ok (it reports false
	// for an unreadable label) and is kept anyway: it states the rule at the decision
	// point rather than relying on a caller's invariant, and it keeps the gate aligned
	// with nextInteractionTarget, which skips unreadable labels up front. It tests
	// labelIsReadable rather than non-emptiness so a glyph-only label is skipped here
	// too, even if a caller ever passes ok=true for one.
	return ok && labelIsReadable(label) && !isDestructiveLabel(label)
}

// isDestructiveLabel reports whether a control's label looks destructive or
// session-ending and should not be clicked by the interaction pass.
func isDestructiveLabel(label string) bool {
	l := strings.ToLower(strings.TrimSpace(label))
	if l == "" {
		return false
	}
	for _, phrase := range destructiveLabelPhrases {
		if strings.Contains(l, phrase) {
			return true
		}
	}
	// Whole-word match for the single-word verbs, over the same split labelIsReadable
	// uses, so "a label with no words" and "a label with no destructive word" cannot
	// diverge: "Delete?" and "delete/remove" match while "Dropdown" and "Payment" do not.
	for _, word := range labelWords(l) {
		if slices.Contains(destructiveLabelWords, word) {
			return true
		}
	}
	return false
}

// normalizeLabel is the identity used to decide whether two controls are "the
// same" control for interaction purposes.
func normalizeLabel(label string) string {
	return strings.ToLower(strings.TrimSpace(label))
}

// nextInteractionTarget returns the index of the next label the interaction pass
// should click, or -1 when none remains. It skips blank labels, skips
// destructive/session-ending controls (isDestructiveLabel), and skips labels whose
// normalized form is already in used — clicking two controls with the same text
// rarely reveals new surface, and used is also what stops the caller from
// re-clicking the same control after it re-queries the DOM.
//
// It returns ONE index rather than a whole plan because the caller re-queries the
// page's elements before every click: a click can re-render or replace nodes, so
// an index computed against an earlier scan may no longer identify the same
// element. Pure and unit-tested so the click policy is verifiable without a browser.
func nextInteractionTarget(labels []string, used map[string]bool) int {
	for i, label := range labels {
		if interactionCandidate(label, used) {
			return i
		}
	}
	return -1
}

// interactionCandidate is the per-label click policy: skip blanks (including
// labels that failed to read), skip destructive or session-ending controls, and
// skip a label already clicked on this page. Factored out of
// nextInteractionTarget so collectInteractionElements can apply the identical
// rule while reading labels lazily — two copies of this predicate would let the
// eager and lazy paths disagree about what is clickable.
func interactionCandidate(label string, used map[string]bool) bool {
	norm := normalizeLabel(label)
	// labelIsReadable rather than norm != "": a glyph-only label is non-empty and
	// matches no destructive word, so a non-emptiness test admitted it here as well.
	return labelIsReadable(label) && !isDestructiveLabel(label) && !used[norm]
}

// currentPageURL returns the page's current document URL and whether it could be
// read. Used to detect that a click navigated.
//
// The ok return is not decoration: page.Info() errors precisely when a document is
// mid-navigation, which is exactly the state the navigation check exists to catch.
// This used to return a bare string with "" meaning unreadable, which made an
// unreadable URL indistinguishable from a value and let the caller's comparison
// silently fail OPEN — the pass kept clicking on a document the worker was never
// assigned, and reported navigated=false so DOM enrichment ran against it. Every
// caller must now decide what an unreadable URL means, and the compiler makes them
// (LAB-4678 review, QUAL-007/SEC-BE-008).
func currentPageURL(page *rod.Page) (string, bool) {
	info, err := page.Info()
	if err != nil || info == nil {
		return "", false
	}
	return info.URL, info.URL != ""
}

// leftAssignedPage is the pure post-click decision for whether the worker may
// still be off its assigned document, split out so the fail-closed rule is
// unit-testable without a browser (the same reason networkIdleReached and
// budgetReached are factored out).
//
// It reports true when recovery must be attempted: either the URL changed, or it
// could not be read at all. The unreadable case is the load-bearing one —
// page.Info() fails while a document is mid-navigation, so after a click "cannot
// read" is evidence of navigation, not evidence of staying put. Reading it as
// "unchanged" is what let the pass keep clicking a foreign document and then
// report navigated=false so DOM enrichment ran against it.
func leftAssignedPage(now string, readable bool, startURL string) bool {
	return !readable || now != startURL
}

// collectInteractionElements queries the page for every interaction selector and
// returns the matched elements, the labels it read, and the index of the first
// element the click policy accepts (-1 when none does). Element-query failures are
// non-fatal (a selector may simply not match).
//
// Labels are read LAZILY: the scan stops at the first acceptable element, so
// labels after that index are left blank and were never fetched. Each
// elementLabel is four CDP round trips (Text plus three Attribute reads), and
// interactPage re-queries before every click, so eagerly labeling every match
// cost maxInteractionsPerPage x matches x 4 round trips — on a page with 200
// controls, roughly 6,400 round trips, all charged against that page's deadline
// (CodeRabbit review, PR #189). The caller only ever uses labels[idx], so the
// rest was work spent to be discarded.
//
// An unreadable label is failed closed on elementLabel's ok, not on the blank
// label it also returns today. The two are equivalent right now, but only because
// elementLabel discards the partial text it may already have read — a version that
// returned that text alongside ok=false would leave the blank check protecting
// nothing. clickAllowed takes ok for the same reason; nextInteractionTarget cannot,
// since it receives already-read labels with no per-label signal, which is why the
// check sits here rather than inside interactionCandidate.
//
// The retained match count is capped at maxInteractionCandidates so page content
// cannot drive this function's allocation size; see that constant for why
// truncating costs no coverage.
func collectInteractionElements(page *rod.Page, used map[string]bool) (rod.Elements, []string, int) {
	var elements rod.Elements
	for _, sel := range interactionSelectors {
		els, err := page.Elements(sel)
		if err != nil {
			continue // non-fatal: selector may not match
		}
		// Retain at most maxInteractionCandidates across all selectors. A page
		// controls how many elements match, so accumulating every match let page
		// content dictate this function's allocation size (SEC-BE-007).
		if room := maxInteractionCandidates - len(elements); len(els) > room {
			els = els[:room]
		}
		elements = append(elements, els...)
		if len(elements) >= maxInteractionCandidates {
			break
		}
	}
	labels := make([]string, len(elements))
	for i, el := range elements {
		label, ok := elementLabel(el)
		labels[i] = label
		if ok && interactionCandidate(label, used) {
			return elements, labels, i
		}
	}
	return elements, labels, -1
}

// interactPage clicks a bounded, non-destructive set of interactive elements on
// the stabilized page to surface endpoints that only fire on user interaction
// (clicks and client-side route changes), waiting for the network to settle
// after each so triggered requests are captured (LAB-4678 Phase 2). Every step
// is best-effort: element-query, label-read, and click failures are all
// non-fatal, and the pass stops early on context cancellation. Captured requests
// accumulate in the shared capture.
//
// It reports whether a click NAVIGATED the page away from the document the worker
// was assigned. Two behaviors follow from that, both fixing the same root cause —
// the pass previously neither detected nor recovered from a navigating click:
//
//   - The element list is re-queried before every click instead of being scanned
//     once up front. interactionSelectors includes bare "button", which matches a
//     <button> inside a <form> (HTML-default type=submit, a full navigation).
//     After such a click every handle from a pre-click scan is stale, so Click
//     errored and the remaining candidates were skipped — one navigating control
//     positioned ahead of the useful ones cost the whole page's interaction
//     coverage, making coverage depend on sibling order. Re-querying costs one CDP
//     round trip per selector plus the label reads up to the first clickable
//     element, and makes the handles valid by construction.
//   - A click that navigates is detected and the page is brought BACK to the
//     assigned document before the pass continues. Returning is what preserves
//     coverage regardless of where the navigating control sits, and it keeps every
//     later click on the document this worker was actually assigned. Clicking on
//     the navigated-to document instead would attribute another page's surface to
//     this one: that page consumed no --max-pages slot and its requests would
//     still be tagged with this page's capture.pageURL.
//
// It returns true only when the page could NOT be brought back, i.e. when the live
// DOM is not the assigned document. visitPage uses that to skip DOM enrichment,
// which otherwise reads page.Info() (the navigated-to URL) as its base and pushes
// another page's links and forms into the frontier off-budget.
//
// It is opt-in (engineOptions.Interact) and off by default: clicking is
// inherently riskier than passive capture (it can mutate state), so it must be
// explicitly requested.
//
// Coverage: the click policy helpers (isDestructiveLabel, nextInteractionTarget,
// clickAllowed) are unit tested; the end-to-end behavior — that an
// interaction-only endpoint is captured only with Interact on, that a navigating
// submit button ahead of the useful control does not cost its coverage, and that
// destructive controls are never fired whichever label source names them — is
// covered by TestRodEngine_Interact_* in the integration suite (-tags=integration).
func (e *rodEngine) interactPage(ctx context.Context, page *rod.Page, capture *pageNetworkCapture, deadline time.Time) (navigated bool) {
	if page == nil {
		return false
	}
	// Without a readable start URL there is no baseline to compare against after a
	// click, so this page's navigation check would have nothing to detect and no
	// click on it can be made safely. Skip the pass entirely rather than clicking
	// blind. Returning false is correct and not a fail-open: nothing has
	// been clicked yet, so the live document is still the assigned one and DOM
	// enrichment is safe. The fail-closed decision here is "do not click", not
	// "assume we navigated".
	startURL, ok := currentPageURL(page)
	if !ok {
		return false
	}
	used := make(map[string]bool, maxInteractionsPerPage)

	for range maxInteractionsPerPage {
		if ctx.Err() != nil {
			return false
		}
		// The page deadline is shared with the baseline network-idle wait, so
		// stop clicking once this page has used its budget rather than letting
		// each click start a fresh wait.
		if !time.Now().Before(deadline) {
			return false
		}

		// Re-query on every iteration: a previous click may have re-rendered or
		// replaced nodes, which invalidates any handle held across it.
		elements, labels, idx := collectInteractionElements(page, used)
		if idx < 0 {
			return false // nothing left to click
		}
		// Mark before clicking so a control that fails to click is not retried on
		// the next iteration (which would spin on it for the whole budget).
		used[normalizeLabel(labels[idx])] = true

		// Re-read the label immediately before clicking. The scan above is
		// time-of-check-to-time-of-use: rendering between the scan and the click can
		// leave a valid handle pointing at a destructive action that was not present
		// when the scan read it. clickAllowed fails closed on an unreadable label;
		// TestClickAllowed covers that gate and
		// TestRodEngine_Interact_SkipsDestructiveControls (build tag: integration)
		// covers it end to end.
		if label, ok := elementLabel(elements[idx]); !clickAllowed(label, ok) {
			continue
		}
		// Best-effort click; a stale handle or a non-clickable element is non-fatal.
		if err := elements[idx].Click(proto.InputMouseButtonLeft, 1); err != nil {
			continue
		}
		// Let requests triggered by the click settle so they are captured.
		e.waitForNetworkIdle(ctx, capture, deadline)

		// A navigating click (a form submit button, a link-like control) leaves us
		// on a document this worker was not assigned. Go back to the assigned page
		// and keep going: the remaining controls still need exercising, and `used`
		// keeps this one from being clicked again. If we cannot get back, report it
		// so the caller does not enrich from the wrong document.
		//
		// An UNREADABLE post-click URL counts as navigated. page.Info() fails while a
		// document is mid-navigation, so "cannot read" after a click is evidence of
		// the very thing being tested for, not evidence of staying put. Treating it
		// as unchanged is what let the pass keep clicking a foreign document.
		now, readable := currentPageURL(page)
		if leftAssignedPage(now, readable, startURL) {
			if !e.returnToPage(ctx, page, startURL, capture, deadline) {
				return true
			}
		}
	}
	return false
}

// returnToPage re-navigates page to url after an interaction click navigated away,
// and reports whether the assigned document is loaded again. The reload's own
// requests are allowed to settle into the shared capture, which also makes the DOM
// queryable for the next click. Bounded by the same per-page deadline as every
// other wait, so restoring cannot extend the page past its budget.
func (e *rodEngine) returnToPage(ctx context.Context, page *rod.Page, url string, capture *pageNetworkCapture, deadline time.Time) bool {
	if err := page.Navigate(url); err != nil {
		return false
	}
	if err := page.WaitLoad(); err != nil && ctx.Err() != nil {
		return false
	}
	e.waitForNetworkIdle(ctx, capture, deadline)
	// An unreadable URL cannot confirm the assigned document is loaded, so it is a
	// failure to restore, not a success.
	now, ok := currentPageURL(page)
	return ok && now == url
}
