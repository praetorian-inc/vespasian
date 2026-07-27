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
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// maxInteractionsPerPage bounds how many elements the interaction pass clicks on
// a single page, so a page with hundreds of buttons cannot blow the page budget
// or hang the crawl. Interaction is opt-in (engineOptions.Interact) and off by
// default (LAB-4678 Phase 2).
const maxInteractionsPerPage = 8

// interactionSelectors are the DOM selectors for elements likely to trigger
// client-side behavior (XHR/fetch or a client-side route change) when clicked,
// without a full navigation. Anchors are excluded: their hrefs are already
// discovered by extractLinks and pushed to the frontier.
var interactionSelectors = []string{
	"button",
	"[role=button]",
	"[onclick]",
}

// destructiveLabelSubstrings are lowercase substrings that mark a control as
// likely destructive or session-ending. The interaction pass skips these so a
// click does not delete data or drop the crawl's authenticated session. The
// list is deliberately conservative — false negatives (a destructive control
// with an unusual label) are possible, so interaction stays opt-in.
var destructiveLabelSubstrings = []string{
	"delete", "remove", "destroy", "drop",
	"logout", "log out", "sign out", "signout",
	"deactivate", "deregister", "unsubscribe", "cancel subscription",
	"reset", "wipe", "clear all", "revoke", "purge",
	// Unambiguous destructive verbs. Bare "cancel" is deliberately NOT here: a
	// dialog's Cancel button is safe and skipping it would lose real surface.
	"trash", "discard", "erase", "terminate", "archive", "close account",
}

// labelAttributes are attributes that carry a control's accessible or fallback
// label. An icon-only or symbol control ("x", an SVG glyph) has no meaningful
// text node, so its actual meaning lives here — and a destructive action has to
// be recognizable from any of them, not from visible text alone.
var labelAttributes = []string{"aria-label", "title", "value"}

// elementLabel returns everything that describes a control: its visible text
// plus every label-bearing attribute, joined so isDestructiveLabel matches a
// destructive verb wherever it appears. Best-effort — unreadable pieces are
// skipped rather than discarding the element.
func elementLabel(el *rod.Element) string {
	var parts []string
	if txt, err := el.Text(); err == nil && strings.TrimSpace(txt) != "" {
		parts = append(parts, txt)
	}
	for _, attr := range labelAttributes {
		v, err := el.Attribute(attr)
		if err == nil && v != nil && strings.TrimSpace(*v) != "" {
			parts = append(parts, *v)
		}
	}
	return strings.Join(parts, " ")
}

// isDestructiveLabel reports whether a control's label looks destructive or
// session-ending and should not be clicked by the interaction pass.
func isDestructiveLabel(label string) bool {
	l := strings.ToLower(strings.TrimSpace(label))
	if l == "" {
		return false
	}
	for _, sub := range destructiveLabelSubstrings {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// selectInteractionTargets returns the indices of labels that the interaction
// pass should click, in order: it skips destructive/session-ending controls
// (isDestructiveLabel), skips blank labels, de-duplicates by normalized label
// (clicking two controls with the same text rarely reveals new surface), and
// caps the result at maxInteractionsPerPage. Pure and unit-tested so the click
// policy is verifiable without a browser.
func selectInteractionTargets(labels []string, max int) []int {
	if max <= 0 {
		return nil
	}
	var out []int
	seen := make(map[string]bool, len(labels))
	for i, label := range labels {
		norm := strings.ToLower(strings.TrimSpace(label))
		if norm == "" || isDestructiveLabel(label) || seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, i)
		if len(out) >= max {
			break
		}
	}
	return out
}

// interactPage clicks a bounded, non-destructive set of interactive elements on
// the stabilized page to surface endpoints that only fire on user interaction
// (clicks and client-side route changes), waiting for the network to settle
// after each so triggered requests are captured (LAB-4678 Phase 2). Every step
// is best-effort: element-query, label-read, and click failures are all
// non-fatal, and the pass stops early on context cancellation. Captured requests
// accumulate in the shared capture; this function returns nothing.
//
// It is opt-in (engineOptions.Interact) and off by default: clicking is
// inherently riskier than passive capture (it can mutate state), so it must be
// explicitly requested.
//
// Coverage: the click policy helpers (isDestructiveLabel,
// selectInteractionTargets) are unit tested; the end-to-end behavior — that an
// interaction-only endpoint is captured only with Interact on, and that
// destructive controls are never fired whichever label source names them — is
// covered by TestRodEngine_Interact_* in the integration suite (-tags=integration).
func (e *rodEngine) interactPage(ctx context.Context, page *rod.Page, capture *pageNetworkCapture, deadline time.Time) {
	if page == nil {
		return
	}
	var elements rod.Elements
	for _, sel := range interactionSelectors {
		els, err := page.Elements(sel)
		if err != nil {
			continue // non-fatal: selector may not match
		}
		elements = append(elements, els...)
	}
	if len(elements) == 0 {
		return
	}

	labels := make([]string, len(elements))
	for i, el := range elements {
		labels[i] = elementLabel(el)
	}

	for _, idx := range selectInteractionTargets(labels, maxInteractionsPerPage) {
		if ctx.Err() != nil {
			return
		}
		// The page deadline is shared with the baseline network-idle wait, so
		// stop clicking once this page has used its budget rather than letting
		// each click start a fresh wait.
		if !time.Now().Before(deadline) {
			return
		}
		// Re-check the label immediately before clicking. The up-front vetting is
		// time-of-check-to-time-of-use: an earlier click can re-render this
		// control in place, and a handle that stayed valid may now point at a
		// destructive action the original scan never saw.
		if isDestructiveLabel(elementLabel(elements[idx])) {
			continue
		}
		// Best-effort click; a stale handle (e.g. after a prior click navigated
		// or re-rendered the DOM) or a non-clickable element is non-fatal.
		if err := elements[idx].Click(proto.InputMouseButtonLeft, 1); err != nil {
			continue
		}
		// Let requests triggered by the click settle so they are captured.
		e.waitForNetworkIdle(ctx, capture, deadline)
	}
}
