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

// Package main provides a simple SOAP service for live testing of vespasian.
// It serves a WSDL file and responds to SOAP requests for user operations.
package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// SOAPEnvelope wraps a SOAP request or response body.
type SOAPEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    SOAPBody `xml:"Body"`
}

// SOAPBody is the body of a SOAP envelope.
type SOAPBody struct {
	Content []byte `xml:",innerxml"`
}

// User is a user record.
type User struct {
	ID    int    `xml:"id"`
	Name  string `xml:"name"`
	Email string `xml:"email"`
}

var users = []User{
	{ID: 1, Name: "Alice", Email: "alice@example.com"},
	{ID: 2, Name: "Bob", Email: "bob@example.com"},
	{ID: 3, Name: "Charlie", Email: "charlie@example.com"},
}

func soapResponse(operation string, body string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://localhost/soap">
  <soap:Body>
    <tns:%sResponse>
      %s
    </tns:%sResponse>
  </soap:Body>
</soap:Envelope>`, operation, body, operation)
}

func xmlEscape(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		return s
	}
	return b.String()
}

func soapFault(code, message string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>%s</faultcode>
      <faultstring>%s</faultstring>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>`, xmlEscape(code), xmlEscape(message))
}

func handleGetUser() string {
	return soapResponse("GetUser", fmt.Sprintf(
		"<id>%d</id><name>%s</name><email>%s</email>",
		users[0].ID, xmlEscape(users[0].Name), xmlEscape(users[0].Email)))
}

func handleListUsers() string {
	var sb strings.Builder
	for _, u := range users {
		fmt.Fprintf(&sb, "<user><id>%d</id><name>%s</name><email>%s</email></user>", u.ID, xmlEscape(u.Name), xmlEscape(u.Email))
	}
	return soapResponse("ListUsers", sb.String())
}

func handleCreateUser() string {
	u := User{ID: len(users) + 1, Name: "NewUser", Email: "new@example.com"}
	return soapResponse("CreateUser", fmt.Sprintf(
		"<id>%d</id><name>%s</name><email>%s</email>",
		u.ID, xmlEscape(u.Name), xmlEscape(u.Email)))
}

func handleSOAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprint(w, soapFault("soap:Client", "Method not allowed")) //nolint:errcheck // test server best-effort response
		return
	}

	soapAction := strings.Trim(r.Header.Get("SOAPAction"), `"`)

	var operation string
	switch {
	case strings.HasSuffix(soapAction, "GetUser"):
		operation = "GetUser"
	case strings.HasSuffix(soapAction, "ListUsers"):
		operation = "ListUsers"
	case strings.HasSuffix(soapAction, "CreateUser"):
		operation = "CreateUser"
	default:
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, soapFault("soap:Client", "Unknown SOAPAction: "+soapAction)) //nolint:errcheck // test server best-effort response
		return
	}

	var response string
	switch operation {
	case "GetUser":
		response = handleGetUser()
	case "ListUsers":
		response = handleListUsers()
	case "CreateUser":
		response = handleCreateUser()
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	fmt.Fprint(w, response) //nolint:errcheck // test server best-effort response
}

func handleWSDL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read WSDL from disk so the served WSDL matches the reference file.
	execDir, err := os.Executable()
	if err != nil {
		execDir = "."
	} else {
		execDir = filepath.Dir(execDir)
	}

	// Try multiple locations for the WSDL file.
	candidates := []string{
		filepath.Join(execDir, "service.wsdl"),
		"service.wsdl",
		filepath.Join(filepath.Dir(os.Args[0]), "service.wsdl"),
	}

	// Also check WSDL_PATH environment variable.
	if p := os.Getenv("WSDL_PATH"); p != "" {
		candidates = append([]string{p}, candidates...)
	}

	var wsdlData []byte
	for _, path := range candidates {
		data, readErr := os.ReadFile(path)
		if readErr == nil {
			wsdlData = data
			break
		}
	}

	if wsdlData == nil {
		http.Error(w, "WSDL file not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write(wsdlData) //nolint:errcheck // test server best-effort response
}

func handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<!DOCTYPE html>\n<html>\n<head><title>Vespasian Test SOAP Service</title></head>\n<body>\n<h1>Vespasian Test SOAP Service</h1>\n<ul>\n  <li><a href=\"/service.wsdl\">Service WSDL</a></li>\n  <li>POST /soap - SOAP Endpoint (use SOAPAction header)</li>\n</ul>\n<h2>Operations</h2>\n<ul>\n  <li>GetUser (SOAPAction: urn:GetUser)</li>\n  <li>ListUsers (SOAPAction: urn:ListUsers)</li>\n  <li>CreateUser (SOAPAction: urn:CreateUser)</li>\n</ul>\n</body>\n</html>") //nolint:errcheck // test server best-effort response
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8991"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/service.wsdl", handleWSDL)
	mux.HandleFunc("/soap", handleSOAP)

	addr := ":" + port
	log.Printf("soap-service listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
