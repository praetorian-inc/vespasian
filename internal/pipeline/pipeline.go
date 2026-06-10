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
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/generate"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// Options configures ClassifyProbeGenerate.
type Options struct {
	// APIType is one of APITypeREST, APITypeWSDL, APITypeGraphQL.
	APIType string

	// Confidence is the classifier match threshold (0.0-1.0).
	Confidence float64

	// Probe enables active endpoint probing.
	Probe bool

	// Deduplicate enables endpoint deduplication after classification.
	Deduplicate bool

	// AllowPrivate disables SSRF protection on probes (allow private/internal IPs).
	AllowPrivate bool

	// Status is an optional io.Writer for verbose status messages.
	// Pass nil or io.Discard to suppress.
	Status io.Writer
}

// ClassifyProbeGenerate runs the classify → probe → generate pipeline and
// returns the produced spec bytes.
func ClassifyProbeGenerate(ctx context.Context, requests []crawl.ObservedRequest, opts Options) ([]byte, error) {
	classifiers := ClassifiersForType(opts.APIType)
	if classifiers == nil {
		return nil, fmt.Errorf("unsupported API type: %q", opts.APIType)
	}

	classified := classify.RunClassifiers(classifiers, requests, opts.Confidence)
	if opts.Deduplicate {
		classified = classify.Deduplicate(classified)
	}

	writeStatus(opts.Status, "classified %d API requests (threshold=%.2f)\n", len(classified), opts.Confidence)

	if opts.Probe {
		cfg := probe.DefaultConfig()
		if opts.AllowPrivate {
			cfg.URLValidator = func(string) error { return nil }
			cfg.Client = &http.Client{
				Timeout: 15 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Transport: &http.Transport{
					TLSHandshakeTimeout:   10 * time.Second,
					ResponseHeaderTimeout: 10 * time.Second,
				},
			}
		}
		strategies := StrategiesForType(opts.APIType, cfg)
		enriched, probeErrs := probe.RunStrategies(ctx, strategies, classified)
		for _, e := range probeErrs {
			writeStatus(opts.Status, "probe warning: %v\n", e)
		}
		classified = enriched
	}

	gen, err := generate.Get(opts.APIType)
	if err != nil {
		return nil, err
	}

	spec, err := gen.Generate(classified)
	if err != nil {
		return nil, fmt.Errorf("generate failed: %w", err)
	}

	return spec, nil
}
