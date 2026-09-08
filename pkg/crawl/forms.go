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

// discoveredForm is a DOM form with its action, method and fields.
type discoveredForm struct {
	Action      string            // resolved absolute URL
	Method      string            // GET or POST
	ContentType string            // application/x-www-form-urlencoded (default)
	Fields      map[string]string // name → value (defaults or placeholders)
}

// extractForms reads every <form> in the DOM. See resolveFormAction for why
// pageURL and baseURL are both needed.
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

		method, err := form.Attribute("method")
		if err == nil && method != nil {
			df.Method = strings.ToUpper(strings.TrimSpace(*method))
		}
		if df.Method == "" {
			df.Method = "GET"
		}

		action, err := form.Attribute("action")
		rawAction := ""
		if err == nil && action != nil {
			rawAction = *action
		}
		resolved, ok := resolveFormAction(rawAction, pageURL, baseURL)
		if !ok {
			continue // skip forms with unparseable actions
		}
		df.Action = resolved

		enctype, err := form.Attribute("enctype")
		if err == nil && enctype != nil && *enctype != "" {
			df.ContentType = strings.TrimSpace(*enctype)
		}

		extractFormFields(form, df.Fields)

		forms = append(forms, df)
	}

	return forms, nil
}

// resolveFormAction returns the absolute submit URL, or ("", false) for
// unparseable or non-navigable actions so the caller drops the form.
//
// An empty action submits to the document URL per HTML §4.10.21.3 — pageURL, NOT
// the base href. A non-empty one resolves against baseURL.
func resolveFormAction(rawAction, pageURL, baseURL string) (string, bool) {
	if strings.TrimSpace(rawAction) == "" {
		return pageURL, true
	}
	resolved, err := resolveURL(baseURL, rawAction)
	if err != nil {
		return "", false
	}
	return resolved, true
}

// formsToObservedRequests makes fields query params for GET, a URL-encoded body
// otherwise.
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
			formData := url.Values{}
			for k, v := range f.Fields {
				formData.Set(k, v)
			}
			obs.Body = []byte(formData.Encode())
			obs.Headers["content-type"] = f.ContentType

			if u, err := url.Parse(f.Action); err == nil {
				obs.QueryParams = CapQueryValues(u.Query())
			}
		} else {
			if u, err := url.Parse(f.Action); err == nil {
				q := u.Query()
				for k, v := range f.Fields {
					q.Set(k, v)
				}
				CapQueryValues(q) // mutates in place; cap before encode so URL matches QueryParams
				u.RawQuery = q.Encode()
				obs.URL = u.String()
				obs.QueryParams = q
			}
		}

		results = append(results, obs)
	}
	return results
}

// extractFormFields reads input, select and textarea children.
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

// isSkippableInputType covers submit, button, image, file and reset.
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

// getInputValue falls back to placeholder, then "".
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
