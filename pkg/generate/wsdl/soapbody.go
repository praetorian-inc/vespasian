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
	"time"
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
	// Namespace is the XML namespace URI of the operation element. It is set
	// only on the top-level result of extractSOAPParameters (walkOperation);
	// nested Children subtrees leave it empty because leaf parameters are
	// emitted unqualified. InferWSDL reads this top-level value (via
	// typesNamespace) to set the generated WSDL/XSD targetNamespace, so the
	// service's observed namespace is preserved in the emitted output.
	Namespace   string
	OrderedKeys []string
	Params      map[string]*inferredParam
}

// inferredParam is one observed parameter under the operation element.
// Leaf params have XSDType set; complex params have Children populated.
// The parameter element's own namespace is intentionally not recorded: the
// generated schema is document/literal with the default unqualified element
// form, so leaf parameters are emitted without a namespace prefix and only the
// enclosing operation/schema namespace is preserved.
type inferredParam struct {
	Name      string
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

// shouldUpgradeWith reports whether p (the existing observation) should be
// replaced by candidate. True iff p carries no type info and candidate does.
// This is the first-with-type-wins rule used by walkOperation (sibling
// elements with the same name), walkParam (repeated child elements), and
// merge (cross-observation aggregation). Centralizing the predicate keeps
// the invariant in one place so future tweaks edit a single site.
func (p *inferredParam) shouldUpgradeWith(candidate *inferredParam) bool {
	return !p.hasType() && candidate.hasType()
}

// addOrUpgrade records param under its element name. A first observation is
// appended in document order; a later same-name sibling replaces the stored
// one only under first-with-type-wins (see inferredParam.shouldUpgradeWith).
// Centralizes the insert/upgrade step shared by walkOperation, walkParam, and
// merge so the ordered-key bookkeeping lives in one place.
func (info *soapBodyInfo) addOrUpgrade(param *inferredParam) {
	existing, seen := info.Params[param.Name]
	if !seen {
		info.OrderedKeys = append(info.OrderedKeys, param.Name)
		info.Params[param.Name] = param
		return
	}
	if existing.shouldUpgradeWith(param) {
		info.Params[param.Name] = param
	}
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
			return walkOperation(decoder, t)
		}
	}
}

// walkOperation walks the operation element and its parameter children.
// It is non-recursive and invoked exactly once per envelope (the operation
// element is the Body's first child, conceptual depth 1), so it needs no
// depth cap of its own; the operation's direct parameters start at depth 2,
// and the recursion bound lives in walkParam.
func walkOperation(decoder *xml.Decoder, opStart xml.StartElement) *soapBodyInfo {
	info := &soapBodyInfo{
		Namespace: opStart.Name.Space,
		Params:    make(map[string]*inferredParam),
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
			// Same-name siblings (XML arrays / repeated elements) collapse via
			// first-with-type-wins inside addOrUpgrade.
			info.addOrUpgrade(walkParam(decoder, t, 2))
		}
	}
}

// walkParam extracts type information from a single parameter element.
func walkParam(decoder *xml.Decoder, paramStart xml.StartElement, depth int) *inferredParam {
	p := &inferredParam{Name: paramStart.Name.Local}

	// Rule 1: xsi:type wins
	if xsiType := findXSIType(paramStart.Attr); xsiType != "" {
		p.XSDType = resolveXSIType(xsiType)
		// Consume the rest of the element (content is irrelevant; type is already known).
		_ = decoder.Skip() //nolint:errcheck // best-effort consume; type is already recorded
		return p
	}

	// Collect text and children until the matching end element.
	var text strings.Builder
collect:
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if t.Name == paramStart.Name {
				break collect
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
					Params: make(map[string]*inferredParam),
				}
			}
			// Same-name children collapse via first-with-type-wins.
			p.Children.addOrUpgrade(walkParam(decoder, t, depth+1))
		}
	}
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

// isPlausibleDate reports whether text is a real calendar date. The lexical
// shape (YYYY-MM-DD, 10 chars) is already gated by dateRe; the length guard
// keeps this helper safe when called directly. time.Parse then rejects
// calendar-impossible values a simple range check would accept — 2026-02-31,
// 2026-04-31, or a Feb-29 in a non-leap year — none of which validate against
// xs:date, so they must fall through to xsd:string rather than be mistyped.
func isPlausibleDate(text string) bool {
	if len(text) != 10 {
		return false
	}
	_, err := time.Parse("2006-01-02", text)
	return err == nil
}

// isPlausibleDateTime reports whether text is a real calendar date-time.
// datetimeRe has already gated the lexical shape; time.Parse additionally
// rejects out-of-range clock fields (e.g. 99:99:99) that the regex's \d{2}
// classes accept. Two layouts cover the datetimeRe variants — without and with
// an explicit zone (Z or numeric offset). Go's parser accepts an optional
// fractional second after the seconds field for both layouts, so the
// ".123"/".123Z" forms need no separate layout.
func isPlausibleDateTime(text string) bool {
	for _, layout := range []string{
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05Z07:00",
	} {
		if _, err := time.Parse(layout, text); err == nil {
			return true
		}
	}
	return false
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
	// Rule 8: dateTime (also reject out-of-range clock fields like 99:99:99)
	if datetimeRe.MatchString(text) && isPlausibleDateTime(text) {
		return "xsd:dateTime"
	}
	// Rule 9: string fallback
	return "xsd:string"
}

// merge unions parameters from b into a. First-with-type wins on conflict —
// a later observation can upgrade an empty-typed parameter, but never
// overwrite a typed one with an empty one.
func (a *soapBodyInfo) merge(b *soapBodyInfo) {
	if a.Namespace == "" && b.Namespace != "" {
		a.Namespace = b.Namespace
	}
	for _, k := range b.OrderedKeys {
		bParam := b.Params[k]
		// Both observations are already typed-complex: first wins, but recurse
		// so nested children union too (e.g. <user><name/></user> then
		// <user><age/></user> across captures).
		if existing, ok := a.Params[k]; ok &&
			existing.IsComplex && bParam.IsComplex &&
			existing.Children != nil && bParam.Children != nil {
			// The Namespace propagation at the top of merge is a no-op here:
			// nested Children.Namespace is always empty (only the top-level
			// operation namespace is recorded). Recursion just unions children.
			existing.Children.merge(bParam.Children)
			continue
		}
		// New parameter, or an empty existing one upgraded by a typed
		// observation (first-with-type-wins; see inferredParam.shouldUpgradeWith).
		// Required for the <status/> then <status>active</status> sequence
		// across captures.
		a.addOrUpgrade(bParam)
	}
}

// typesNamespace chooses the XML namespace for the generated WSDL and its
// embedded XSD schema. It prefers the namespace observed on the operation
// elements in the SOAP traffic, so the generated schema reflects the service's
// real namespace rather than a URL-derived guess. It falls back to urlDerived
// when no operation carried a namespace, or when operations disagreed: a single
// WSDL targetNamespace cannot represent several at once, and splitting into
// per-namespace schemas is deferred (architecture §11). Using one namespace for
// definitions, tns, and schema keeps every tns: reference resolvable.
func typesNamespace(operations []string, observations map[string]*soapBodyInfo, urlDerived string) string {
	observed := ""
	for _, opName := range operations {
		info := observations[opName]
		if info == nil || info.Namespace == "" {
			continue
		}
		switch observed {
		case "":
			observed = info.Namespace
		case info.Namespace:
			// same namespace again — still unambiguous
		default:
			return urlDerived // operations disagree; fall back
		}
	}
	if observed == "" {
		return urlDerived
	}
	return observed
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
