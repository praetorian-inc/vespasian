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
	"sync"

	"github.com/go-rod/rod/lib/launcher"
)

// BrowserOptions configures Chrome launch parameters.
type BrowserOptions struct {
	Headless   bool
	NoSandbox  bool
	ChromePath string // optional: path to system Chrome binary
}

// BrowserManager owns the Chrome process lifecycle. It launches Chrome via
// go-rod's launcher and retains the handle so vespasian can kill the browser
// immediately on signal, stopping all outbound requests.
type BrowserManager struct {
	launcher *launcher.Launcher
	wsURL    string
	killOnce sync.Once
}

// NewBrowserManager launches a Chrome instance with the given options and
// returns a manager that owns its lifecycle.
func NewBrowserManager(opts BrowserOptions) (*BrowserManager, error) {
	l := launcher.New().
		Headless(opts.Headless)

	if opts.NoSandbox {
		l = l.NoSandbox(true)
	}
	if opts.ChromePath != "" {
		l = l.Bin(opts.ChromePath)
	}

	wsURL, err := l.Launch()
	if err != nil {
		return nil, err
	}

	return &BrowserManager{
		launcher: l,
		wsURL:    wsURL,
	}, nil
}

// WSURL returns the Chrome DevTools Protocol WebSocket URL. Pass this to
// Katana's ChromeWSUrl option so it connects to our browser instead of
// launching its own.
func (b *BrowserManager) WSURL() string {
	return b.wsURL
}

// Kill immediately terminates the Chrome process. This stops all outbound
// network requests. Safe to call multiple times.
func (b *BrowserManager) Kill() {
	b.killOnce.Do(func() {
		b.launcher.Kill()
	})
}

// Cleanup waits for Chrome to exit and removes the temporary user data
// directory. Call this after Kill to ensure full cleanup.
func (b *BrowserManager) Cleanup() {
	b.launcher.Cleanup()
}

// Close kills Chrome (if still running) and cleans up resources. Intended
// for use with defer in the normal (non-signal) path.
func (b *BrowserManager) Close() {
	b.Kill()
	b.Cleanup()
}

// PID returns the Chrome process ID, useful for testing.
func (b *BrowserManager) PID() int {
	return b.launcher.PID()
}
