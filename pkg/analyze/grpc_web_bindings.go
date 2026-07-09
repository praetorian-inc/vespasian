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

package analyze

import (
	"log/slog"
	"sort"
	"strings"

	"github.com/BishopFox/jsluice"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// maxGRPCWebBundleSize caps the JS body size processed per capture entry,
// mirroring jsstatic.DefaultMaxBundleSize. Bundles larger than this are skipped
// to bound parse work.
const maxGRPCWebBundleSize = 5 * 1024 * 1024 // 5 MB

// ExtractGRPCWebBindings scans the JavaScript response bodies in a capture for
// generated gRPC-Web / Connect client artifacts and recovers service/method/type
// names and streaming flags. It mirrors pkg/analyze/jsstatic: it reads each
// entry's Response.Body, runs jsluice over JS-content-type bodies, and returns
// the recovered services deduplicated by fully-qualified service name.
//
// Returns nil when no bindings are found.
func ExtractGRPCWebBindings(captured []crawl.ObservedRequest) []classify.GRPCService {
	// Accumulate methods per service FQN; a service may be split across bundles.
	byService := map[string]map[string]classify.GRPCMethod{}

	for _, req := range captured {
		body := req.Response.Body
		if !isJSContentTypeForGRPC(req.Response.ContentType) || len(body) == 0 {
			continue
		}
		if len(body) > maxGRPCWebBundleSize {
			slog.Debug("grpc-web bindings: skipping oversized bundle", "url", req.URL, "size", len(body))
			continue
		}

		for _, svc := range extractFromJS(body, req.URL) {
			methods, ok := byService[svc.Name]
			if !ok {
				methods = map[string]classify.GRPCMethod{}
				byService[svc.Name] = methods
			}
			for _, m := range svc.Methods {
				// First write wins on collision; bundles for the same service
				// carry identical method shapes.
				if _, exists := methods[m.Name]; !exists {
					methods[m.Name] = m
				}
			}
		}
	}

	return mergeServices(byService)
}

// mergeServices flattens the per-service method map into a sorted slice with
// sorted methods for deterministic output.
func mergeServices(byService map[string]map[string]classify.GRPCMethod) []classify.GRPCService {
	if len(byService) == 0 {
		return nil
	}
	names := make([]string, 0, len(byService))
	for name := range byService {
		names = append(names, name)
	}
	sort.Strings(names)

	services := make([]classify.GRPCService, 0, len(names))
	for _, name := range names {
		methodMap := byService[name]
		methodNames := make([]string, 0, len(methodMap))
		for mn := range methodMap {
			methodNames = append(methodNames, mn)
		}
		sort.Strings(methodNames)

		svc := classify.GRPCService{Name: name}
		for _, mn := range methodNames {
			svc.Methods = append(svc.Methods, methodMap[mn])
		}
		services = append(services, svc)
	}
	return services
}

// isJSContentTypeForGRPC reports whether ct indicates a JavaScript body. It
// replicates the (6-line) jsstatic predicate rather than importing the
// unexported original (Rule of Three not yet met).
func isJSContentTypeForGRPC(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.Contains(lower, "javascript") ||
		strings.Contains(lower, "ecmascript") ||
		lower == "text/js" ||
		lower == "application/x-js"
}

// extractFromJS runs the binding detectors over one JS source body. baseURL is
// used only for diagnostic logging. ExtractGRPCWebBindings fans out over the
// capture and merges results.
func extractFromJS(jsSource []byte, baseURL string) []classify.GRPCService {
	if len(jsSource) == 0 {
		return nil
	}
	analyzer := jsluice.NewAnalyzer(jsSource)

	byService := map[string]map[string]classify.GRPCMethod{}
	add := func(svcFQN string, m classify.GRPCMethod) {
		if svcFQN == "" || m.Name == "" {
			return
		}
		methods, ok := byService[svcFQN]
		if !ok {
			methods = map[string]classify.GRPCMethod{}
			byService[svcFQN] = methods
		}
		if _, exists := methods[m.Name]; !exists {
			methods[m.Name] = m
		}
	}

	detectConnectES(analyzer, add)
	detectPBService(analyzer, add)
	detectGRPCWebMethodDescriptors(analyzer, add)

	out := mergeServices(byService)
	if len(out) > 0 {
		slog.Debug("grpc-web bindings: recovered services", "url", baseURL, "services", len(out))
	}
	return out
}

// detectConnectES recovers Connect-ES service definitions of the shape:
//
//	export const UserService = {
//	  typeName: "users.v1.UserService",
//	  methods: {
//	    getUser: { name: "GetUser", I: GetUserRequest, O: GetUserResponse, kind: MethodKind.Unary },
//	    watchUsers: { name: "WatchUsers", I: WatchRequest, O: User, kind: MethodKind.ServerStreaming },
//	  },
//	}
//
// It walks object literals, identifies those carrying a typeName + methods
// object, and maps each method entry to a GRPCMethod.
func detectConnectES(analyzer *jsluice.Analyzer, add func(string, classify.GRPCMethod)) {
	analyzer.Query("(object) @obj", func(n *jsluice.Node) {
		obj := n.AsObject()
		if !obj.HasValidNode() {
			return
		}
		typeName := obj.GetString("typeName", "")
		methodsNode := obj.GetNode("methods")
		if typeName == "" || methodsNode == nil || methodsNode.Type() != "object" {
			return
		}

		methodsObj := methodsNode.AsObject()
		for _, key := range methodsObj.GetKeys() {
			methodNode := methodsObj.GetNode(key)
			if methodNode == nil || methodNode.Type() != "object" {
				continue
			}
			mo := methodNode.AsObject()

			name := mo.GetString("name", "")
			if name == "" {
				// Fall back to the property key when no explicit name literal.
				name = key
			}
			method := classify.GRPCMethod{
				Name:       name,
				InputType:  identifierName(mo.GetNode("I"), name+"Request"),
				OutputType: identifierName(mo.GetNode("O"), name+"Response"),
			}
			applyMethodKind(mo.GetNode("kind"), &method)
			add(typeName, method)
		}
	})
}

// detectPBService recovers grpc-web *_pb_service.js stubs of the shape:
//
//	UserService.serviceName = "users.v1.UserService";
//	UserService.GetUser = {
//	  methodName: "GetUser",
//	  requestStream: false,
//	  responseStream: false,
//	  requestType: GetUserRequest,
//	  responseType: GetUserResponse,
//	};
//
// Method-descriptor objects carry methodName + request/response stream flags.
// The owning service FQN is taken from the matching `<Service>.serviceName`
// assignment; absent that, methods are skipped (no reliable FQN).
func detectPBService(analyzer *jsluice.Analyzer, add func(string, classify.GRPCMethod)) {
	// Pass 1: map local service identifier → service FQN via `X.serviceName = "..."`.
	serviceFQN := map[string]string{}
	analyzer.Query("(assignment_expression) @assign", func(n *jsluice.Node) {
		left := n.ChildByFieldName("left")
		right := n.ChildByFieldName("right")
		if left == nil || right == nil || left.Type() != "member_expression" {
			return
		}
		objNode := left.ChildByFieldName("object")
		propNode := left.ChildByFieldName("property")
		if objNode == nil || propNode == nil || propNode.Content() != "serviceName" {
			return
		}
		if right.Type() != "string" {
			return
		}
		serviceFQN[objNode.Content()] = trimJSString(right.Content())
	})

	if len(serviceFQN) == 0 {
		return
	}

	// Pass 2: map `X.<Method> = { methodName, requestStream, responseStream, ... }`.
	analyzer.Query("(assignment_expression) @assign", func(n *jsluice.Node) {
		if fqn, method, ok := pbServiceMethodFromAssignment(n, serviceFQN); ok {
			add(fqn, method)
		}
	})
}

// pbServiceMethodFromAssignment parses a grpc-web method-descriptor assignment
// (`X.<Method> = { methodName, requestStream, responseStream, requestType,
// responseType }`) into a service FQN + GRPCMethod. Returns ok=false when the
// node is not such an assignment or the owning service FQN is unknown.
func pbServiceMethodFromAssignment(n *jsluice.Node, serviceFQN map[string]string) (string, classify.GRPCMethod, bool) {
	left := n.ChildByFieldName("left")
	right := n.ChildByFieldName("right")
	if left == nil || right == nil || left.Type() != "member_expression" || right.Type() != "object" {
		return "", classify.GRPCMethod{}, false
	}
	objNode := left.ChildByFieldName("object")
	if objNode == nil {
		return "", classify.GRPCMethod{}, false
	}
	fqn, ok := serviceFQN[objNode.Content()]
	if !ok {
		return "", classify.GRPCMethod{}, false
	}

	mo := right.AsObject()
	name := mo.GetString("methodName", "")
	if name == "" {
		return "", classify.GRPCMethod{}, false
	}
	method := classify.GRPCMethod{
		Name:            name,
		InputType:       identifierName(mo.GetNode("requestType"), name+"Request"),
		OutputType:      identifierName(mo.GetNode("responseType"), name+"Response"),
		ClientStreaming: boolLiteral(mo.GetNode("requestStream")),
		ServerStreaming: boolLiteral(mo.GetNode("responseStream")),
	}
	return fqn, method, true
}

// detectGRPCWebMethodDescriptors recovers grpc-web *_grpc_web_pb.js descriptors
// of the shape:
//
//	new grpc.web.MethodDescriptor('/users.v1.UserService/GetUser',
//	  grpc.web.MethodType.UNARY, RequestType, ResponseType, ...)
//
// Service FQN and method name are parsed from the "/pkg.Service/Method" path;
// streaming is derived from the MethodType argument.
func detectGRPCWebMethodDescriptors(analyzer *jsluice.Analyzer, add func(string, classify.GRPCMethod)) {
	analyzer.Query("(new_expression) @new", func(n *jsluice.Node) {
		ctor := n.ChildByFieldName("constructor")
		if ctor == nil || !strings.Contains(ctor.Content(), "MethodDescriptor") {
			return
		}
		args := n.ChildByFieldName("arguments")
		if args == nil {
			return
		}

		pathArg := args.NamedChild(0)
		if pathArg == nil || pathArg.Type() != "string" {
			return
		}
		svcFQN, methodName := splitMethodPath(trimJSString(pathArg.Content()))
		if svcFQN == "" || methodName == "" {
			return
		}

		method := classify.GRPCMethod{
			Name:       methodName,
			InputType:  identifierName(args.NamedChild(2), methodName+"Request"),
			OutputType: identifierName(args.NamedChild(3), methodName+"Response"),
		}
		applyMethodType(args.NamedChild(1), &method)
		add(svcFQN, method)
	})
}

// applyMethodKind sets streaming flags from a Connect-ES `kind: MethodKind.*`
// reference. Unary leaves both flags false.
func applyMethodKind(n *jsluice.Node, m *classify.GRPCMethod) {
	if n == nil {
		return
	}
	switch {
	case strings.Contains(n.Content(), "BiDiStreaming"):
		m.ClientStreaming = true
		m.ServerStreaming = true
	case strings.Contains(n.Content(), "ClientStreaming"):
		m.ClientStreaming = true
	case strings.Contains(n.Content(), "ServerStreaming"):
		m.ServerStreaming = true
	}
}

// applyMethodType sets streaming flags from a grpc-web
// `grpc.web.MethodType.UNARY|SERVER_STREAMING` reference.
func applyMethodType(n *jsluice.Node, m *classify.GRPCMethod) {
	if n == nil {
		return
	}
	if strings.Contains(n.Content(), "SERVER_STREAMING") {
		m.ServerStreaming = true
	}
}

// identifierName returns the message class name referenced by node n. The
// generated message type is a JS identifier (GetUserRequest) or a
// module-qualified member expression (users_pb.GetUserRequest,
// proto.users.v1.GetUserRequest). The JS module qualifier is a bundler
// namespace, not a proto package, so only the final identifier segment is
// kept; FileDescriptorsFromServices re-qualifies it with the service's proto
// package. When the node is missing or unusable, fallback is returned so the
// rpc line still renders.
func identifierName(n *jsluice.Node, fallback string) string {
	if n == nil || !n.IsValid() {
		return fallback
	}
	content := strings.TrimSpace(n.Content())
	// A string-literal type name (rare) is unquoted; an identifier is used as-is.
	if n.Type() == "string" {
		content = trimJSString(content)
	}
	// Drop a JS module/namespace qualifier, keeping the final class name.
	if idx := strings.LastIndex(content, "."); idx >= 0 {
		content = content[idx+1:]
	}
	if content == "" {
		return fallback
	}
	return content
}

// boolLiteral reports whether n is the JS literal `true`.
func boolLiteral(n *jsluice.Node) bool {
	return n != nil && n.IsValid() && n.Content() == "true"
}

// trimJSString strips surrounding quote characters from a JS string literal.
func trimJSString(s string) string {
	return strings.Trim(s, "\"'`")
}

// splitMethodPath parses a "/pkg.Service/Method" gRPC path into (serviceFQN,
// method). Returns ("", "") when the path is not in that form.
func splitMethodPath(path string) (svcFQN, method string) {
	path = strings.TrimPrefix(path, "/")
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return "", ""
	}
	return path[:idx], path[idx+1:]
}
