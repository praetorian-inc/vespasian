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

// RESTClassifier classifies REST API requests.
type RESTClassifier struct{}

// Name returns the classifier name.
func (c *RESTClassifier) Name() string {
	return "rest"
}

// Classify determines if the request is a REST API call.
func (c *RESTClassifier) Classify(_ crawl.ObservedRequest) (bool, float64) {
	return false, 0
}
