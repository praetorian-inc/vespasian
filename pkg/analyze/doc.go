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

// Package analyze statically analyses captured response bodies to surface
// endpoints and parameters the capture itself never exercised. It runs between
// capture and classification.
//
// ExtractForms tokenizes HTML bodies and emits one synthetic ObservedRequest per
// <form>, tagged Source="static:html". It complements pkg/crawl's DOM extractor
// (Source="form"), which only runs during a live headless crawl — so imported
// Burp, HAR and mitmproxy traffic gets form coverage too.
//
// ExtractGRPCWebBindings runs jsluice over captured JS to recover gRPC
// service/method/type names and streaming flags from generated gRPC-Web and
// Connect-ES clients, for the reflection-off discovery path. Names only, no
// message fields.
package analyze
