package classify_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

func TestClassifiedRequest_ProbeFieldsSerialization(t *testing.T) {
	req := classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method: "GET",
			URL:    "https://api.example.com/users",
		},
		IsAPI:          true,
		Confidence:     0.95,
		AllowedMethods: []string{"GET", "POST", "OPTIONS"},
		ResponseSchema: map[string]interface{}{
			"type": "object",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded classify.ClassifiedRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.AllowedMethods) != 3 {
		t.Errorf("AllowedMethods: got %d, want 3", len(decoded.AllowedMethods))
	}
	if decoded.ResponseSchema == nil {
		t.Error("ResponseSchema: got nil, want non-nil")
	}
}

func TestClassifiedRequest_ProbeFieldsOmitEmpty(t *testing.T) {
	req := classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method: "GET",
			URL:    "https://api.example.com/users",
		},
		IsAPI:      true,
		Confidence: 0.9,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	jsonStr := string(data)
	if strings.Contains(jsonStr, "allowed_methods") {
		t.Error("allowed_methods should be omitted when nil")
	}
	if strings.Contains(jsonStr, "response_schema") {
		t.Error("response_schema should be omitted when nil")
	}
}
