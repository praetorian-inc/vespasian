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

package pipeline_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
)

// ---------------------------------------------------------------------------
// TEST-005: IsStaticAssetURL — comprehensive extension table coverage
// ---------------------------------------------------------------------------

// staticAssetExtensions mirrors the list in static_asset.go. The test builds
// a synthetic URL per extension and asserts IsStaticAssetURL returns true, so
// any accidental deletion or typo in the source list fails here.
var staticAssetExtensions = []string{
	".css", ".js", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".webmanifest",
	".mp4", ".webm", ".mp3", ".ogg",
}

func TestIsStaticAssetURL_AllExtensions(t *testing.T) {
	for _, ext := range staticAssetExtensions {
		ext := ext
		t.Run(ext, func(t *testing.T) {
			rawURL := fmt.Sprintf("https://example.com/assets/file%s", ext)
			assert.True(t, pipeline.IsStaticAssetURL(rawURL), "expected true for %s", rawURL)
		})
	}
}

func TestIsStaticAssetURL_NonStaticPath(t *testing.T) {
	assert.False(t, pipeline.IsStaticAssetURL("https://example.com/api/v1/users"))
}

func TestIsStaticAssetURL_ExtensionInQueryOnly(t *testing.T) {
	// .js appears only in the query string, not the path — should not match.
	assert.False(t, pipeline.IsStaticAssetURL("https://example.com/api?cb=x.js"))
}

func TestIsStaticAssetURL_UnparsableURLReturnsFalse(t *testing.T) {
	// "://bad" is not a valid URL; the function must return false without panicking.
	assert.False(t, pipeline.IsStaticAssetURL("://bad"))
}

func TestIsStaticAssetURL_EmptyString(t *testing.T) {
	assert.False(t, pipeline.IsStaticAssetURL(""))
}

func TestIsStaticAssetURL_UppercaseExtension(t *testing.T) {
	// Extension matching is case-insensitive.
	assert.True(t, pipeline.IsStaticAssetURL("https://example.com/image.PNG"))
}
