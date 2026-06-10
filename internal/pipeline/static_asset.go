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
	"net/url"
	"strings"
)

// staticAssetExtensions is the list of file extensions that identify static assets.
// Ported from guard/backend/pkg/lib/web/url.go.
var staticAssetExtensions = []string{
	".css", ".js", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".webmanifest",
	".mp4", ".webm", ".mp3", ".ogg",
}

// IsStaticAssetURL returns true when the URL path has a static-asset extension.
// Ported from guard/backend/pkg/lib/web/url.go.
func IsStaticAssetURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	lower := strings.ToLower(parsed.Path)
	for _, ext := range staticAssetExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
