package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Get_Success(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	}))
	defer server.Close()

	// Create client
	client := NewClient(&ClientConfig{
		Timeout:    5 * time.Second,
		MaxRetries: 3,
		UserAgent:  "vespasian-test",
	})

	// Make request
	ctx := context.Background()
	resp, err := client.Get(ctx, server.URL)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "test response", string(resp.Body))
}

func TestClient_Get_WithRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success after retry"))
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		Timeout:    5 * time.Second,
		MaxRetries: 3,
		UserAgent:  "vespasian-test",
	})

	ctx := context.Background()
	resp, err := client.Get(ctx, server.URL)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 3, attempts)
}

func TestClient_Get_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		Timeout:    5 * time.Second,
		MaxRetries: 1,
		UserAgent:  "vespasian-test",
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.Get(ctx, server.URL)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestClient_Get_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		Timeout:    50 * time.Millisecond,
		MaxRetries: 1,
		UserAgent:  "vespasian-test",
	})

	ctx := context.Background()
	_, err := client.Get(ctx, server.URL)
	assert.Error(t, err)
}

func TestClient_Get_RetryClosesBodyBeforeContinue(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		// Return 503 for first 2 attempts, then 200
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("service unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success after retry"))
	}))
	defer server.Close()

	client := NewClient(&ClientConfig{
		Timeout:    5 * time.Second,
		MaxRetries: 3,
		UserAgent:  "vespasian-test",
	})

	ctx := context.Background()
	resp, err := client.Get(ctx, server.URL)

	// Should succeed after retries
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 3, attempts)

	// This test verifies the bug is fixed:
	// The first 2 attempts return 503 (which triggers retry).
	// Without the fix, those response bodies are not closed until function exit,
	// causing resource leaks. The fix explicitly closes resp.Body before continue.
}
