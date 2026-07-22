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

// DetectAPIType runs lightweight classification against all three API types and
// picks the winner. GraphQL wins when it has matches and at least as many as
// both others. WSDL wins when it has matches and at least as many as REST.
// Otherwise REST is returned.
//
// The count-comparison is deliberate: it selects the DOMINANT surface, so a
// mostly-REST app with one incidental SOAP/GraphQL-looking request is still
// typed REST (and a weak signal like a lone text/xml response cannot flip the
// whole capture). A prior LAB-4678 Phase 3 attempt to make GraphQL/WSDL win on
// presence alone was reverted: it flipped the type on weak/minority signals and
// discarded the dominant REST surface for mixed apps. The run-to-run verdict
// instability the ticket targets comes from capture-count variance upstream,
// which the Phase 0/1 determinism work addresses; there is no
// DetectAPIType-level change that improves stability without breaking
// dominant-surface selection.
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

	var wsdlCount, restCount, graphqlCount int
	for _, req := range requests {
		if isAPI, confidence := wsdlClassifier.Classify(req); isAPI && confidence >= threshold {
			wsdlCount++
		}
		if isAPI, confidence := restClassifier.Classify(req); isAPI && confidence >= threshold {
			restCount++
		}
		if isAPI, confidence := graphqlClassifier.Classify(req); isAPI && confidence >= threshold {
			graphqlCount++
		}
	}

	// GraphQL wins when it has matches and at least as many as both others.
	if graphqlCount > 0 && graphqlCount >= wsdlCount && graphqlCount >= restCount {
		return APITypeGraphQL
	}
	// WSDL wins when it has at least one match and at least as many as REST
	// (ties favor WSDL). GraphQL is already resolved above.
	if wsdlCount > 0 && wsdlCount >= restCount {
		return APITypeWSDL
	}
	return APITypeREST
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
