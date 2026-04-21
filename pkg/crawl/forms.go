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
	"net/url"
	"strings"

	"github.com/go-rod/rod"
)

// discoveredForm represents a form found in the DOM with its action, method,
// and input fields extracted.
type discoveredForm struct {
	Action      string            // resolved absolute URL
	Method      string            // GET or POST
	ContentType string            // application/x-www-form-urlencoded (default)
	Fields      map[string]string // name → value (defaults or placeholders)
}

// extractForms finds all <form> elements in the page DOM and extracts their
// action, method, and input fields. Explicit action="…" attributes are
// resolved against baseURL (the page's <base href>-aware base) so that
// relative refs on SPA routes produce the same URL the browser would submit
// to. When a form has no action attribute the HTML spec (§4.10.21.3) says
// the form submits to the document's URL — pageURL here — *not* the base
// href, so no-action forms keep the current route.
func extractForms(page *rod.Page, pageURL, baseURL string) ([]discoveredForm, error) {
	formElements, err := page.Elements("form")
	if err != nil {
		return nil, err
	}

	var forms []discoveredForm
	for _, form := range formElements {
		df := discoveredForm{
			ContentType: "application/x-www-form-urlencoded",
			Fields:      make(map[string]string),
		}

		// Extract method (default GET).
		method, err := form.Attribute("method")
		if err == nil && method != nil {
			df.Method = strings.ToUpper(strings.TrimSpace(*method))
		}
		if df.Method == "" {
			df.Method = "GET"
		}

		// Extract and resolve action URL.
		action, err := form.Attribute("action")
		if err == nil && action != nil && *action != "" {
			resolved, err := resolveURL(baseURL, *action)
			if err != nil {
				continue // skip forms with unparseable actions
			}
			df.Action = resolved
		} else {
			// No action attribute — HTML spec says the form submits to the
			// document's URL. Using baseURL here would place no-action
			// forms at the <base href>-resolved root (e.g., "/" on a page
			// served from /login), reporting the wrong endpoint.
			df.Action = pageURL
		}

		// Extract enctype if specified.
		enctype, err := form.Attribute("enctype")
		if err == nil && enctype != nil && *enctype != "" {
			df.ContentType = strings.TrimSpace(*enctype)
		}

		// Extract input fields: <input>, <select>, <textarea>.
		extractFormFields(form, df.Fields)

		forms = append(forms, df)
	}

	return forms, nil
}

// formsToObservedRequests converts discovered forms into synthetic
// ObservedRequest entries. For GET forms, the fields become query parameters.
// For POST forms, the fields become a URL-encoded body.
func formsToObservedRequests(forms []discoveredForm, pageURL string) []ObservedRequest {
	var results []ObservedRequest
	for _, f := range forms {
		obs := ObservedRequest{
			Method:  f.Method,
			URL:     f.Action,
			Source:  "form",
			PageURL: pageURL,
		}

		if f.Method == "POST" {
			obs.Headers = map[string]string{}
			// Encode fields as URL-encoded form body.
			formData := url.Values{}
			for k, v := range f.Fields {
				formData.Set(k, v)
			}
			obs.Body = []byte(formData.Encode())
			obs.Headers["content-type"] = f.ContentType

			// Parse query params from the action URL.
			if u, err := url.Parse(f.Action); err == nil {
				obs.QueryParams = make(map[string]string)
				for key, values := range u.Query() {
					if len(values) > 0 {
						obs.QueryParams[key] = values[0]
					}
				}
			}
		} else {
			// GET form: merge fields into query params.
			if u, err := url.Parse(f.Action); err == nil {
				q := u.Query()
				for k, v := range f.Fields {
					q.Set(k, v)
				}
				u.RawQuery = q.Encode()
				obs.URL = u.String()

				obs.QueryParams = make(map[string]string)
				for key, values := range u.Query() {
					if len(values) > 0 {
						obs.QueryParams[key] = values[0]
					}
				}
			}
		}

		results = append(results, obs)
	}
	return results
}

// extractFormFields populates the fields map from a form element's input,
// select, and textarea children.
func extractFormFields(form *rod.Element, fields map[string]string) {
	inputs, err := form.Elements("input[name], select[name], textarea[name]")
	if err != nil {
		return
	}
	for _, input := range inputs {
		name, err := input.Attribute("name")
		if err != nil || name == nil || *name == "" {
			continue
		}

		if isSkippableInputType(input) {
			continue
		}

		fields[*name] = getInputValue(input)
	}
}

// isSkippableInputType returns true for input types that don't carry API data
// (submit, button, image, file, reset).
func isSkippableInputType(input *rod.Element) bool {
	inputType, err := input.Attribute("type")
	if err != nil || inputType == nil {
		return false
	}
	switch strings.ToLower(*inputType) {
	case "submit", "button", "image", "file", "reset":
		return true
	}
	return false
}

// getInputValue returns the value attribute of an input, falling back to
// the placeholder attribute, or empty string.
func getInputValue(input *rod.Element) string {
	val, err := input.Attribute("value")
	if err == nil && val != nil && *val != "" {
		return *val
	}
	placeholder, err := input.Attribute("placeholder")
	if err == nil && placeholder != nil && *placeholder != "" {
		return *placeholder
	}
	return ""
}
