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
	"math"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// API type constants used for classification routing and generation.
const (
	APITypeAuto    = "auto"
	APITypeREST    = "rest"
	APITypeWSDL    = "wsdl"
	APITypeGraphQL = "graphql"
	APITypeGRPC    = "grpc"
)

// Dominance rule constants for DetectAPIType (LAB-4678).
const (
	// MinChallengerMatches is the absolute floor a non-REST type must clear
	// before it can take the verdict. It is 1 because the weak-signal problem is
	// already handled upstream by exclusive assignment (see DetectAPIType): a
	// lone text/xml response scores higher on REST than on WSDL and is therefore
	// never a WSDL vote in the first place. The floor remains as an explicit
	// guard so a zero-vote type can never win.
	MinChallengerMatches = 1

	// DominanceMargin is how far a challenger must exceed the REST tally to win.
	// A challenger needs count >= ceil(restCount * DominanceMargin), so the
	// verdict does not sit on a knife edge where one more or one fewer captured
	// request flips the whole generator.
	DominanceMargin = 1.5

	// scoreEpsilon absorbs floating-point accumulation error when comparing two
	// classifier confidences for the tie-break below. Confidences are built by
	// addition — RESTClassifier reaches 0.95 as 0.8 + 0.15, which evaluates to
	// 0.9500000000000001 — so a specialist scoring a literal 0.95 would lose an
	// intended tie by 1e-16. Comparing within this tolerance makes the tie-break
	// depend on the intended score, not on the order the score was summed in.
	scoreEpsilon = 1e-9
)

// atLeast reports whether a is greater than or equal to b within scoreEpsilon.
func atLeast(a, b float64) bool { return a >= b-scoreEpsilon }

// DetectAPIType runs lightweight classification against all three API types and
// picks the dominant surface. GraphQL is resolved first, then WSDL; REST is the
// default and the fallback.
//
// Each request votes for at most ONE type: the classifier that scores it highest
// at or above threshold, with REST winning ties. Previously every classifier that
// matched a request counted it, so a single SOAP envelope incremented both the
// WSDL tally (0.90) and the REST tally (0.80). That double-counting is what made
// the tallies incomparable — a challenger could never out-count a REST surface
// that included all of the challenger's own requests — and it is why the old rule
// had to fall back to >= ties, which is what put the verdict on a knife edge.
//
// A challenger type (GraphQL, WSDL) then takes the verdict only when it clears
// BOTH MinChallengerMatches and the DominanceMargin over REST — see challengerWins.
//
// Why not a plain count comparison (the pre-LAB-4678 rule): comparing raw counts
// with >= ties put the verdict on a knife edge. (rest=10, gql=10) typed the app
// GraphQL while (rest=11, gql=10) typed it REST, so a single extra or missing
// observation switched the generator and the whole emitted spec. Truncated and
// timing-variant captures move counts by exactly that much, which is the
// run-to-run verdict instability this ticket targets. That rule also let
// (rest=0, wsdl=1) emit a WSDL spec off one stray text/xml.
//
// Why not presence-wins: an earlier LAB-4678 Phase 3 attempt made GraphQL/WSDL
// win on having any match at all. It was reverted because it flipped the type on
// weak minority signals and discarded the dominant REST surface of mixed apps.
//
// The floor-plus-margin rule keeps dominant-surface selection — a genuinely
// GraphQL-dominant capture still wins — while being robust to the ±1 observation
// variance that made the old rule unstable, and it fixes the lone-signal case
// that caused the revert.
//
// Note: this performs a lightweight classification pass separate from the full
// RunClassifiers call inside ClassifyProbeGenerate. The duplication is
// intentional — DetectAPIType only needs to answer "which generator?", while
// ClassifyProbeGenerate's pass produces the full ClassifiedRequest slice
// needed for generation.
func DetectAPIType(requests []crawl.ObservedRequest, threshold float64) string {
	wsdlClassifier := &classify.WSDLClassifier{}
	restClassifier := &classify.RESTClassifier{}
	graphqlClassifier := &classify.GraphQLClassifier{}

	// score returns the classifier's confidence when it both matches and clears
	// the threshold, else 0 — so a sub-threshold match cannot win the argmax.
	score := func(c classify.APIClassifier, req crawl.ObservedRequest) float64 {
		if isAPI, confidence := c.Classify(req); isAPI && confidence >= threshold {
			return confidence
		}
		return 0
	}

	var wsdlCount, restCount, graphqlCount int
	for _, req := range requests {
		restScore := score(restClassifier, req)
		wsdlScore := score(wsdlClassifier, req)
		graphqlScore := score(graphqlClassifier, req)

		// Exclusive assignment: the request votes once, for its strongest type.
		// Ties go to the SPECIALIST (GraphQL, then WSDL) rather than to REST,
		// because REST is the generic shape every specialized request also has.
		// A GraphQL call is always additionally "a JSON POST", and /graphql is
		// itself in the REST path allowlist, so REST ties GraphQL at 0.95 on a
		// textbook GraphQL request; giving that tie to REST would make GraphQL
		// undetectable. REST still takes every request no specialist scores at
		// least as highly, and remains the fallback when nothing matches.
		switch {
		case graphqlScore > 0 && atLeast(graphqlScore, restScore) && atLeast(graphqlScore, wsdlScore):
			graphqlCount++
		case wsdlScore > 0 && atLeast(wsdlScore, restScore):
			wsdlCount++
		case restScore > 0:
			restCount++
		}
	}

	// GraphQL is resolved first: it must dominate REST and be AT LEAST AS MANY as
	// WSDL, so a SOAP-heavy capture with a handful of GraphQL-ish requests stays
	// WSDL. A GraphQL/WSDL tie resolves to GraphQL, matching the tie-to-GraphQL
	// ordering of the per-request argmax above; stating it as "out-count WSDL"
	// described a stricter rule than the >= implements (LAB-4678 review, QUAL-001).
	if challengerWins(graphqlCount, restCount) && graphqlCount >= wsdlCount {
		return APITypeGraphQL
	}
	// WSDL next. GraphQL is already resolved above.
	if challengerWins(wsdlCount, restCount) {
		return APITypeWSDL
	}
	return APITypeREST
}

// challengerWins reports whether a non-REST type with challengerCount matches
// beats a REST surface of restCount matches. It requires an absolute floor and a
// relative margin; see the DetectAPIType doc comment for why both are needed.
//
// With restCount == 0 the margin term is 0 and the floor alone decides, so a
// capture containing only challenger-typed requests takes that type. That is
// correct: there is no dominant REST surface to discard. The failure the earlier
// revert cited — one stray text/xml retyping a mostly-REST app — is prevented by
// the margin, not the floor: at rest=20 a challenger needs 30 votes, so a single
// stray cannot flip anything.
func challengerWins(challengerCount, restCount int) bool {
	if challengerCount < MinChallengerMatches {
		return false
	}
	required := int(math.Ceil(float64(restCount) * DominanceMargin))
	return challengerCount >= required
}

// ClassifiersForType returns the appropriate classifiers for the given API type.
func ClassifiersForType(apiType string) []classify.APIClassifier {
	switch apiType {
	case APITypeREST:
		return []classify.APIClassifier{&classify.RESTClassifier{}}
	case APITypeWSDL:
		return []classify.APIClassifier{&classify.WSDLClassifier{}}
	case APITypeGraphQL:
		return []classify.APIClassifier{&classify.GraphQLClassifier{}}
	case APITypeGRPC:
		return []classify.APIClassifier{&classify.GRPCClassifier{}}
	default:
		return nil
	}
}

// StrategiesForType returns the probe strategies for the given API type.
// REST (and the default) get OPTIONS + Schema probes; WSDL gets WSDL probe;
// GraphQL gets GraphQL probe. The gRPC path chains reflection (richest — real
// message fields) then the grpc-gateway OpenAPI probe (names only) in priority
// order; gRPC-Web JS bindings are applied separately by enrichGRPCFromBindings
// since they read the capture rather than the network.
func StrategiesForType(apiType string, cfg probe.Config) []probe.ProbeStrategy {
	switch apiType {
	case APITypeWSDL:
		return []probe.ProbeStrategy{probe.NewWSDLProbe(cfg)}
	case APITypeGraphQL:
		return []probe.ProbeStrategy{probe.NewGraphQLProbe(cfg)}
	case APITypeGRPC:
		return []probe.ProbeStrategy{
			probe.NewGRPCProbe(cfg),
			probe.NewGRPCGatewayProbe(cfg),
		}
	default:
		return []probe.ProbeStrategy{
			probe.NewOptionsProbe(cfg),
			probe.NewSchemaProbe(cfg),
		}
	}
}
