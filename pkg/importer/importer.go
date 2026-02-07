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

// Package importer defines the interface for converting external traffic
// captures into the vespasian ObservedRequest format.
package importer

import (
	"io"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// TrafficImporter converts external traffic captures to ObservedRequest format.
type TrafficImporter interface {
	// Name returns the importer name (e.g., "burp", "har").
	Name() string

	// Import reads external traffic and converts it to ObservedRequest format.
	Import(r io.Reader) ([]crawl.ObservedRequest, error)
}
