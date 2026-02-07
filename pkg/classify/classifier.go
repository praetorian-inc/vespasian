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

package classify

import (
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// APIClassifier determines if a request is an API call.
type APIClassifier interface {
	// Name returns the classifier name (e.g., "rest", "graphql").
	Name() string

	// Classify returns whether the request is an API call and the confidence score.
	Classify(req crawl.ObservedRequest) (bool, float64)
}

// RunClassifiers applies all classifiers to requests and returns classified results.
func RunClassifiers(classifiers []APIClassifier, requests []crawl.ObservedRequest, threshold float64) []ClassifiedRequest {
	var results []ClassifiedRequest

	for _, req := range requests {
		var bestMatch ClassifiedRequest
		bestMatch.ObservedRequest = req
		bestMatch.IsAPI = false
		bestMatch.Confidence = 0

		for _, classifier := range classifiers {
			isAPI, confidence := classifier.Classify(req)
			if isAPI && confidence > bestMatch.Confidence {
				bestMatch.IsAPI = true
				bestMatch.Confidence = confidence
				bestMatch.APIType = classifier.Name()
				bestMatch.Reason = "Classified by " + classifier.Name()
			}
		}

		if bestMatch.Confidence >= threshold {
			results = append(results, bestMatch)
		}
	}

	return results
}
