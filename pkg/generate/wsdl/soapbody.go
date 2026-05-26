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

// This parser uses encoding/xml with all defaults; external entities are not
// resolved. Do not enable Strict=false, Entity, or AutoClose.

package wsdl

import (
	"bytes"
	"encoding/xml"
	"regexp"
	"strings"
)

const (
	soapNS11     = "http://schemas.xmlsoap.org/soap/envelope/"
	soapNS12     = "http://www.w3.org/2003/05/soap-envelope"
	xsiNS        = "http://www.w3.org/2001/XMLSchema-instance"
	maxBodyDepth = 32
)

// Package-level regexes compiled once to avoid per-call overhead.
var (
	boolRe = regexp.MustCompile(`^(true|false)$`)
	// intRe matches signed integer literals. "0" and "-0" match; any other
	// number with a leading zero (e.g. "0123") does NOT match and falls
	// through to xsd:string. Leading-zero strings are typically identifiers
	// (ZIP codes, version segments, padded IDs) that an XSD xs:int parser
	// would silently corrupt.
	intRe      = regexp.MustCompile(`^-?(0|[1-9]\d*)$`)
	decimalRe  = regexp.MustCompile(`^-?\d+\.\d+$`)
	dateRe     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	datetimeRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$`)
)

// soapBodyInfo is the per-request extraction result. nil for failures.
type soapBodyInfo struct {
	// OpNamespace records the namespace URI of the element whose contents this
	// soapBodyInfo represents. At the top-level result of extractSOAPParameters,
	// that element is the operation element. In nested Children subtrees built
	// by walkParam, OpNamespace holds the parent parameter element's namespace,
	// not the operation's — the field is "parent element namespace" in the
	// general case; the operation-namespace reading is correct only at the
	// outermost level.
	// Captured for diagnostic use and merge propagation; not threaded into the
	// emitted XSD because the schema's targetNamespace is URL-derived for
	// consistency with the WSDL Messages wiring (architecture §11).
	OpNamespace string
	OrderedKeys []string
	Params      map[string]*inferredParam
}

// inferredParam is one observed parameter under the operation element.
// Leaf params have XSDType set; complex params have Children populated.
type inferredParam struct {
	Name string
	// Namespace records the observed parameter element's XML namespace URI.
	// Captured for diagnostic use; not threaded into the emitted XSD for the
	// same reason as soapBodyInfo.OpNamespace (architecture §11).
	Namespace string
	XSDType   string
	IsComplex bool
	Children  *soapBodyInfo
}

// hasType reports whether the parameter carries usable type information —
// either a resolved XSD type string or a populated complex-type subtree.
// Used to gate same-name-sibling upgrades so a typed observation is not
// overwritten by a later empty one.
func (p *inferredParam) hasType() bool {
	return p.IsComplex || p.XSDType != ""
}

// extractSOAPParameters walks a SOAP envelope and extracts typed parameters
// from the operation element in the Body. Returns nil on failure or empty body.
func extractSOAPParameters(body []byte) *soapBodyInfo {
	if len(body) == 0 {
		return nil
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	// XXE: defaults are safe — do NOT touch decoder.Entity, decoder.AutoClose, decoder.Strict.

	inBody := false
	for {
		tok, err := decoder.Token()
		if err != nil {
			return nil
		}
		t, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if strings.EqualFold(t.Name.Local, "Body") &&
			(t.Name.Space == soapNS11 || t.Name.Space == soapNS12) {
			inBody = true
			continue
		}
		if inBody {
			return walkOperation(decoder, t, 1)
		}
	}
}

// walkOperation walks the operation element and its parameter children.
func walkOperation(decoder *xml.Decoder, opStart xml.StartElement, depth int) *soapBodyInfo {
	info := &soapBodyInfo{
		OpNamespace: opStart.Name.Space,
		Params:      make(map[string]*inferredParam),
	}
	for {
		tok, err := decoder.Token()
		if err != nil {
			return info
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if t.Name == opStart.Name {
				return info
			}
		case xml.StartElement:
			if depth >= maxBodyDepth {
				_ = decoder.Skip() //nolint:errcheck // best-effort subtree discard; errors here are non-fatal
				continue
			}
			param := walkParam(decoder, t, depth+1)
			existing, seen := info.Params[param.Name]
			if !seen {
				info.OrderedKeys = append(info.OrderedKeys, param.Name)
				info.Params[param.Name] = param
				continue
			}
			// Same-name sibling (XML arrays / repeated elements): first
			// observation with type info wins. Upgrade only if the prior
			// observation was untyped and the new one has type info; never
			// overwrite a typed param with an empty one.
			if !existing.hasType() && param.hasType() {
				info.Params[param.Name] = param
			}
		}
	}
}

// walkParam extracts type information from a single parameter element.
func walkParam(decoder *xml.Decoder, paramStart xml.StartElement, depth int) *inferredParam {
	p := &inferredParam{
		Name:      paramStart.Name.Local,
		Namespace: paramStart.Name.Space,
	}

	// Rule 1: xsi:type wins
	if xsiType := findXSIType(paramStart.Attr); xsiType != "" {
		p.XSDType = resolveXSIType(xsiType)
		// Consume the rest of the element (content is irrelevant; type is already known).
		_ = decoder.Skip() //nolint:errcheck // best-effort consume; type is already recorded
		return p
	}

	// Collect text and children until the matching end element
	var text strings.Builder
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if t.Name == paramStart.Name {
				goto done
			}
		case xml.CharData:
			text.Write(t)
		case xml.StartElement:
			if depth >= maxBodyDepth {
				_ = decoder.Skip() //nolint:errcheck // best-effort subtree discard at depth cap
				continue
			}
			if p.Children == nil {
				p.Children = &soapBodyInfo{
					OpNamespace: paramStart.Name.Space,
					Params:      make(map[string]*inferredParam),
				}
			}
			child := walkParam(decoder, t, depth+1)
			existing, seen := p.Children.Params[child.Name]
			if !seen {
				p.Children.OrderedKeys = append(p.Children.OrderedKeys, child.Name)
				p.Children.Params[child.Name] = child
				continue
			}
			// Same-name sibling under a parent: first-with-type wins (see
			// walkOperation for the same rule).
			if !existing.hasType() && child.hasType() {
				p.Children.Params[child.Name] = child
			}
		}
	}
done:
	if p.Children != nil {
		p.IsComplex = true
		return p
	}
	// Rules 3–9: value-based type inference (empty text is skipped by caller)
	p.XSDType = inferTypeFromValue(strings.TrimSpace(text.String()))
	return p
}

// findXSIType finds the xsi:type attribute value, matching by namespace URI.
func findXSIType(attrs []xml.Attr) string {
	for _, a := range attrs {
		if a.Name.Space == xsiNS && a.Name.Local == "type" {
			return a.Value
		}
	}
	return ""
}

// resolveXSIType maps an xsi:type attribute value to an XSD type string.
// Whitespace around the value is trimmed before parsing. An empty or
// whitespace-only value falls back to xsd:string.
//
// Simple-prefix fallback: only the canonical "xsd" and "xs" prefixes map
// to XSD built-ins (e.g. xs:int → xsd:int). Non-canonical prefixes
// (e.g. ns0:CustomType) ALSO fall back to xsd:string rather than emitting
// a tns:typeName reference — the generator does not synthesize matching
// <complexType> definitions for inferred types, so emitting tns:typeName
// would produce a dangling reference in the WSDL. Losing the type name
// is acceptable for fallback inference; the schema's targetNamespace and
// element ordering are still correct (architecture §11 — full prefix-stack
// resolution and custom-type emission deferred until a corpus demands it).
func resolveXSIType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "xsd:string"
	}
	idx := strings.Index(value, ":")
	if idx < 0 {
		return "xsd:" + value
	}
	prefix := value[:idx]
	localName := value[idx+1:]
	if prefix == "xsd" || prefix == "xs" {
		return "xsd:" + localName
	}
	// Non-canonical prefix: avoid emitting a dangling tns: reference.
	return "xsd:string"
}

// isPlausibleDate does a basic range check for YYYY-MM-DD strings already
// matched by dateRe. Month must be 01–12 and day 01–31.
func isPlausibleDate(text string) bool {
	// text is already validated by dateRe: YYYY-MM-DD (10 chars)
	if len(text) != 10 {
		return false
	}
	mm := text[5:7]
	dd := text[8:10]
	return mm >= "01" && mm <= "12" && dd >= "01" && dd <= "31"
}

// inferTypeFromValue infers an XSD type from a string value.
// Returns "" for empty/whitespace-only values (skip marker per rule 3).
func inferTypeFromValue(text string) string {
	if text == "" {
		return ""
	}
	// Rule 4: boolean (case-sensitive: only true|false)
	if boolRe.MatchString(text) {
		return "xsd:boolean"
	}
	// Rule 5: integer
	if intRe.MatchString(text) {
		return "xsd:int"
	}
	// Rule 6: decimal
	if decimalRe.MatchString(text) {
		return "xsd:decimal"
	}
	// Rule 7: date (also validate month 01-12 and day 01-31 ranges)
	if dateRe.MatchString(text) && isPlausibleDate(text) {
		return "xsd:date"
	}
	// Rule 8: dateTime
	if datetimeRe.MatchString(text) {
		return "xsd:dateTime"
	}
	// Rule 9: string fallback
	return "xsd:string"
}

// merge unions parameters from b into a. First-with-type wins on conflict —
// a later observation can upgrade an empty-typed parameter, but never
// overwrite a typed one with an empty one.
func (a *soapBodyInfo) merge(b *soapBodyInfo) {
	if a.OpNamespace == "" && b.OpNamespace != "" {
		a.OpNamespace = b.OpNamespace
	}
	for _, k := range b.OrderedKeys {
		bParam := b.Params[k]
		existing, ok := a.Params[k]
		if !ok {
			// New parameter — add it
			a.OrderedKeys = append(a.OrderedKeys, k)
			a.Params[k] = bParam
			continue
		}
		// Upgrade: existing was empty (no type, not complex) and the new
		// observation has type info. Required for the <status/> then
		// <status>active</status> sequence across captures.
		if !existing.hasType() && bParam.hasType() {
			a.Params[k] = bParam
			continue
		}
		// Both have type info: first wins; recurse for complex children.
		if existing.IsComplex && bParam.IsComplex && existing.Children != nil && bParam.Children != nil {
			existing.Children.merge(bParam.Children)
		}
	}
}

// inferTypesFromObservations builds a *Types from the aggregated parameter observations.
// Returns nil when observations is empty.
func inferTypesFromObservations(operations []string, observations map[string]*soapBodyInfo, targetNS string) *Types {
	if len(observations) == 0 {
		return nil
	}

	var elements []Element
	for _, opName := range operations {
		info, ok := observations[opName]
		if !ok {
			continue
		}
		el := Element{
			Name:        opName,
			ComplexType: buildComplexType(info),
		}
		elements = append(elements, el)
	}

	if len(elements) == 0 {
		return nil
	}

	return &Types{
		Schemas: []Schema{{
			TargetNS: targetNS,
			XMLNS:    "http://www.w3.org/2001/XMLSchema",
			Elements: elements,
		}},
	}
}

// buildComplexType constructs a ComplexType from a soapBodyInfo.
func buildComplexType(info *soapBodyInfo) *ComplexType {
	var seq []Element
	for _, k := range info.OrderedKeys {
		param := info.Params[k]
		// Skip empty-type parameters (rule 3 — empty text, no children)
		if param.XSDType == "" && !param.IsComplex {
			continue
		}
		var el Element
		if param.IsComplex && param.Children != nil {
			el = Element{
				Name:        param.Name,
				ComplexType: buildComplexType(param.Children),
			}
		} else {
			el = Element{
				Name: param.Name,
				Type: param.XSDType,
			}
		}
		seq = append(seq, el)
	}
	return &ComplexType{
		Sequence: seq,
	}
}
