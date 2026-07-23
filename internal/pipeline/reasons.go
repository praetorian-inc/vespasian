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

package pipeline

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// logClassificationReasons writes one line per classified endpoint to the
// verbose status writer, making the REST-vs-not decision explainable for a
// given input (LAB-4678). Output is deterministic — lines are sorted by
// method+path and each Reason is a pure function of the request — so the same
// input always produces the same explanation. It is a no-op when w is nil (the
// status writer is non-nil only under -v), so default artifacts are unchanged.
func logClassificationReasons(w io.Writer, classified []classify.ClassifiedRequest) {
	if w == nil || len(classified) == 0 {
		return
	}
	lines := make([]string, 0, len(classified))
	for _, c := range classified {
		path := c.URL
		if u, err := url.Parse(c.URL); err == nil && u.Path != "" {
			path = u.Path
		}
		reason := c.Reason
		if reason == "" {
			reason = "-"
		}
		lines = append(lines, fmt.Sprintf("  %-6s %s [type=%s confidence=%.2f reason=%s]",
			strings.ToUpper(c.Method), path, c.APIType, c.Confidence, reason))
	}
	sort.Strings(lines)
	for _, ln := range lines {
		writeStatus(w, "%s\n", ln)
	}
}
