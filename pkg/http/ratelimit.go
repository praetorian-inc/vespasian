package http

import (
	"context"
	"fmt"

	"golang.org/x/time/rate"
)

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	limiter *rate.Limiter
}

// NewRateLimiter creates a rate limiter with specified requests per second
func NewRateLimiter(requestsPerSecond float64) *RateLimiter {
	// Allow burst of 2x the rate for initial requests
	burst := int(requestsPerSecond * 2)
	if burst < 1 {
		burst = 1
	}

	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(requestsPerSecond), burst),
	}
}

// Wait blocks until rate limit allows next request
func (r *RateLimiter) Wait(ctx context.Context) error {
	if err := r.limiter.Wait(ctx); err != nil {
		return fmt.Errorf("context canceled: %w", err)
	}
	return nil
}
