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
}

// isDestructiveLabel reports whether a control's visible label looks destructive
// or session-ending and should not be clicked by the interaction pass.
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
// explicitly requested. Exercised by the integration suite against a live target,
// not the default unit tests.
func (e *rodEngine) interactPage(ctx context.Context, page *rod.Page, capture *pageNetworkCapture) {
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
		if txt, err := el.Text(); err == nil {
			labels[i] = txt
		}
	}

	for _, idx := range selectInteractionTargets(labels, maxInteractionsPerPage) {
		if ctx.Err() != nil {
			return
		}
		// Best-effort click; a stale handle (e.g. after a prior click navigated
		// or re-rendered the DOM) or a non-clickable element is non-fatal.
		if err := elements[idx].Click(proto.InputMouseButtonLeft, 1); err != nil {
			continue
		}
		// Let requests triggered by the click settle so they are captured.
		e.waitForNetworkIdle(ctx, capture)
	}
}
