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

package importer

import (
	"errors"
	"io"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

var (
	// ErrFileTooLarge is returned when the import file exceeds the maximum size (500MB).
	ErrFileTooLarge = errors.New("file exceeds maximum import size (500MB)")

	// ErrTooManyEntries is returned when the import exceeds the maximum entry count.
	ErrTooManyEntries = errors.New("import exceeds maximum entry count")
)

// limitedReader wraps an io.Reader and tracks whether the size limit was exceeded.
type limitedReader struct {
	reader    io.Reader
	remaining int64
	hitLimit  bool
}

func newLimitedReader(r io.Reader, limit int64) *limitedReader {
	return &limitedReader{
		reader:    r,
		remaining: limit,
	}
}

func (lr *limitedReader) Read(p []byte) (n int, err error) {
	if lr.remaining <= 0 {
		lr.hitLimit = true
		return 0, io.EOF
	}

	if int64(len(p)) > lr.remaining {
		p = p[:lr.remaining]
	}

	n, err = lr.reader.Read(p)
	lr.remaining -= int64(n)

	if lr.remaining <= 0 && err == nil {
		lr.hitLimit = true
		err = io.EOF
	}

	return n, err
}

// TrafficImporter converts external traffic captures to ObservedRequest format.
type TrafficImporter interface {
	// Name returns the importer name (e.g., "burp", "har").
	Name() string

	// Import reads external traffic and converts it to ObservedRequest format.
	Import(r io.Reader) ([]crawl.ObservedRequest, error)
}
