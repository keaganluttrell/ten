package resilience

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetry_Success(t *testing.T) {
	calls := 0
	err := Retry(DefaultRetryConfig(), func() error {
		calls++
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 1, calls) // Should succeed on first try
}

func TestRetry_FailThenSucceed(t *testing.T) {
	calls := 0
	err := Retry(RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		Multiplier:     2.0,
	}, func() error {
		calls++
		if calls < 3 {
			return errors.New("temporary error")
		}
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, 3, calls)
}

func TestRetry_AllFail(t *testing.T) {
	calls := 0
	err := Retry(RetryConfig{
		MaxRetries:     2,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
		Multiplier:     2.0,
	}, func() error {
		calls++
		return errors.New("persistent error")
	})

	assert.Error(t, err)
	assert.Equal(t, 3, calls) // Initial + 2 retries
}

func TestCircuitBreaker_NormalOperation(t *testing.T) {
	cb := NewCircuitBreaker(3, 2, 100*time.Millisecond)

	err := cb.Execute(func() error {
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, StateClosed, cb.State())
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(3, 2, 100*time.Millisecond)

	testErr := errors.New("fail")
	for i := 0; i < 3; i++ {
		cb.Execute(func() error { return testErr })
	}

	assert.Equal(t, StateOpen, cb.State())

	// Next call should be rejected
	err := cb.Execute(func() error { return nil })
	assert.Equal(t, ErrCircuitOpen, err)
}

func TestCircuitBreaker_HalfOpenAfterTimeout(t *testing.T) {
	cb := NewCircuitBreaker(2, 2, 10*time.Millisecond)

	// Trip the breaker
	cb.Execute(func() error { return errors.New("fail") })
	cb.Execute(func() error { return errors.New("fail") })
	assert.Equal(t, StateOpen, cb.State())

	// Wait for timeout
	time.Sleep(15 * time.Millisecond)

	// Next call should put it in half-open and succeed
	err := cb.Execute(func() error { return nil })
	assert.NoError(t, err)
	assert.Equal(t, StateHalfOpen, cb.State())

	// One more success should close it
	cb.Execute(func() error { return nil })
	assert.Equal(t, StateClosed, cb.State())
}

func TestBackoffDuration(t *testing.T) {
	initial := 100 * time.Millisecond
	max := 5 * time.Second

	assert.Equal(t, 100*time.Millisecond, BackoffDuration(0, initial, max, 2.0))
	assert.Equal(t, 200*time.Millisecond, BackoffDuration(1, initial, max, 2.0))
	assert.Equal(t, 400*time.Millisecond, BackoffDuration(2, initial, max, 2.0))
	assert.Equal(t, 5*time.Second, BackoffDuration(10, initial, max, 2.0)) // Capped
}
