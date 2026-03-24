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

package main

import (
	"fmt"
	"io"
	"os"
)

// ANSI escape codes for banner styling.
const (
	bannerColorRed   = "\033[31m"
	bannerColorBold  = "\033[1m"
	bannerColorGray  = "\033[90m"
	bannerColorReset = "\033[0m"
)

// banner is the ASCII art displayed on startup (FIGlet "slant" font).
const banner = `
 _    _____________ ____  ___   _____ _______    _   __
| |  / / ____/ ___// __ \/   | / ___//  _/   |  / | / /
| | / / __/  \__ \/ /_/ / /| | \__ \ / // /| | /  |/ /
| |/ / /___ ___/ / ____/ ___ |___/ // // ___ |/ /|  /
|___/_____//____/_/   /_/  |_/____/___/_/  |_/_/ |_/

 Praetorian Security, Inc.
`

// printBanner writes the styled ASCII banner and version info to stderr.
func printBanner() {
	printBannerTo(os.Stderr)
}

// printBannerTo writes the styled ASCII banner and version info to the given writer.
func printBannerTo(w io.Writer) {
	fmt.Fprintf(w, "%s%s%s%s\n", bannerColorBold, bannerColorRed, banner, bannerColorReset) //nolint:errcheck // best-effort banner output
	fmt.Fprintf(w, "%s  v%s%s\n\n", bannerColorGray, version, bannerColorReset)             //nolint:errcheck // best-effort banner output
}
