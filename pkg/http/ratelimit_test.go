package http

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter_Wait_Success(t *testing.T) {
	// 10 requests per second
	limiter := NewRateLimiter(10.0)

	ctx := context.Background()
	start := time.Now()

	// Make 10 requests - should complete quickly
	for i := 0; i < 10; i++ {
		err := limiter.Wait(ctx)
		require.NoError(t, err)
	}

	elapsed := time.Since(start)
	// Should complete in less than 2 seconds (with burst allowance)
	assert.Less(t, elapsed, 2*time.Second)
}

func TestRateLimiter_Wait_EnforcesLimit(t *testing.T) {
	// 2 requests per second
	limiter := NewRateLimiter(2.0)

	ctx := context.Background()
	start := time.Now()

	// Make 6 requests - burst allows 4, then need to wait for 2 more
	for i := 0; i < 6; i++ {
		err := limiter.Wait(ctx)
		require.NoError(t, err)
	}

	elapsed := time.Since(start)
	// Should take at least 500ms (burst allows 4, wait 500ms for 2 more at 2/sec)
	assert.Greater(t, elapsed, 400*time.Millisecond)
}

func TestRateLimiter_Wait_ContextCanceled(t *testing.T) {
	limiter := NewRateLimiter(1.0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := limiter.Wait(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

func TestRateLimiter_Wait_ContextTimeout(t *testing.T) {
	// Very slow rate to ensure we hit timeout
	limiter := NewRateLimiter(0.1)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Exhaust burst tokens (burst = 0.1 * 2 = 0, so burst is 1)
	_ = limiter.Wait(ctx)

	// Next request should fail immediately due to timeout (rate too slow)
	err := limiter.Wait(ctx)
	assert.Error(t, err)
}
