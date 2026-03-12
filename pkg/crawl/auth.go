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

package crawl

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// commonAuthKeys are localStorage key names commonly used by SPAs to store
// auth tokens. When a Bearer token is detected in the -H flag, the token
// value is injected into all of these keys before crawling.
var commonAuthKeys = []string{
	"auth",
	"token",
	"access_token",
	"accessToken",
	"auth_token",
	"authToken",
	"jwt",
	"jwt_token",
	"jwtToken",
	"bearer_token",
	"bearerToken",
	"id_token",
	"idToken",
}

// extractBearerToken extracts a Bearer token from the headers map.
// Returns the token value (without "Bearer " prefix) or empty string if not found.
func extractBearerToken(headers map[string]string) string {
	for key, value := range headers {
		if strings.EqualFold(key, "Authorization") {
			value = strings.TrimSpace(value)
			if strings.HasPrefix(value, "Bearer ") {
				return strings.TrimPrefix(value, "Bearer ")
			}
		}
	}
	return ""
}

// preSeedBrowserAuth creates a Chrome profile directory with auth tokens
// pre-populated in localStorage for the given target origin. This enables
// headless crawling of SPAs that gate API calls on localStorage auth tokens.
//
// The caller is responsible for cleaning up the returned directory.
// Returns the path to the Chrome data directory, or an error.
func preSeedBrowserAuth(targetURL string, token string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("parse target URL: %w", err)
	}
	origin := u.Scheme + "://" + u.Host

	dataDir, err := os.MkdirTemp("", "vespasian-chrome-*")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	cleanup := true
	defer func() {
		if cleanup {
			os.RemoveAll(dataDir)
		}
	}()

	l := launcher.New().
		UserDataDir(dataDir).
		Headless(true).
		Set("no-sandbox").
		Set("disable-gpu")

	browserURL, err := l.Launch()
	if err != nil {
		return "", fmt.Errorf("launch browser: %w", err)
	}

	browser := rod.New().ControlURL(browserURL)
	if err := browser.Connect(); err != nil {
		return "", fmt.Errorf("connect to browser: %w", err)
	}
	defer browser.MustClose()

	page, err := browser.Page(proto.TargetCreateTarget{URL: origin})
	if err != nil {
		return "", fmt.Errorf("open page: %w", err)
	}

	if err := page.WaitLoad(); err != nil {
		slog.Warn("page did not load during auth pre-seed", "url", origin, "error", err)
		// Continue anyway — localStorage injection may still work.
	}

	// Inject the Bearer token into common localStorage key names.
	// SPAs use various key names; injecting into all common ones maximizes
	// compatibility without requiring app-specific configuration.
	for _, key := range commonAuthKeys {
		_, evalErr := page.Eval(`(key, val) => { try { localStorage.setItem(key, val); } catch(e) {} }`, key, token)
		if evalErr != nil {
			slog.Debug("failed to set localStorage key", "key", key, "error", evalErr)
		}
	}

	// Also inject as "Bearer <token>" variants for apps that store the full header value.
	bearerValue := "Bearer " + token
	for _, key := range []string{"auth", "token", "authorization"} {
		_, evalErr := page.Eval(`(key, val) => { try { localStorage.setItem(key, val); } catch(e) {} }`, key+"_header", bearerValue)
		if evalErr != nil {
			slog.Debug("failed to set localStorage header key", "key", key+"_header", "error", evalErr)
		}
	}

	cleanup = false
	return dataDir, nil
}
