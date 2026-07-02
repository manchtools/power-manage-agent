package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fastBackoff shrinks the retry backoff so the bounded-retry tests don't sleep
// out the real 1s→8s schedule. Restored after the test.
func fastBackoff(t *testing.T) {
	t.Helper()
	base, max := firstSyncBaseBackoff, firstSyncMaxBackoff
	t.Cleanup(func() { firstSyncBaseBackoff, firstSyncMaxBackoff = base, max })
	firstSyncBaseBackoff = time.Millisecond
	firstSyncMaxBackoff = time.Millisecond
}

// A first sync that fails a few times (the device→gateway binding race) then
// succeeds must be retried until it lands, returning the success interval — so
// the connection gets its one full reconcile instead of dropping to
// incremental-only mode.
func TestSyncUntilFullReconcile_RetriesUntilSuccess(t *testing.T) {
	fastBackoff(t)
	calls := 0
	iv := syncUntilFullReconcile(context.Background(), quietLogger(), func() time.Duration {
		calls++
		if calls < 3 {
			return 0 // transient failure
		}
		return 30 * time.Minute
	})
	if iv != 30*time.Minute {
		t.Fatalf("interval = %v, want 30m (the first success)", iv)
	}
	if calls != 3 {
		t.Fatalf("syncOnce called %d times, want 3 (2 failures + 1 success)", calls)
	}
}

// A success on the first attempt returns immediately with no retry.
func TestSyncUntilFullReconcile_FirstTrySucceeds(t *testing.T) {
	calls := 0
	iv := syncUntilFullReconcile(context.Background(), quietLogger(), func() time.Duration {
		calls++
		return 5 * time.Minute
	})
	if iv != 5*time.Minute || calls != 1 {
		t.Fatalf("iv=%v calls=%d, want 5m and 1 call", iv, calls)
	}
}

// A persistently-failing sync exhausts the bounded attempts and returns 0
// (the caller then falls back to periodic/manual sync) rather than looping
// forever.
func TestSyncUntilFullReconcile_ExhaustsAndReturnsZero(t *testing.T) {
	fastBackoff(t)
	calls := 0
	iv := syncUntilFullReconcile(context.Background(), quietLogger(), func() time.Duration {
		calls++
		return 0
	})
	if iv != 0 {
		t.Fatalf("interval = %v, want 0 on persistent failure", iv)
	}
	if calls != firstSyncMaxAttempts {
		t.Fatalf("syncOnce called %d times, want %d (bounded)", calls, firstSyncMaxAttempts)
	}
}

// A cancelled context aborts the retry promptly (the stream ended) instead of
// sleeping out the backoff.
func TestSyncUntilFullReconcile_CtxCancelAborts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	done := make(chan time.Duration, 1)
	go func() {
		done <- syncUntilFullReconcile(ctx, quietLogger(), func() time.Duration {
			calls++
			return 0 // always fail so it would retry if not for ctx
		})
	}()
	select {
	case iv := <-done:
		if iv != 0 {
			t.Fatalf("interval = %v, want 0 on ctx cancel", iv)
		}
		if calls != 1 {
			t.Fatalf("syncOnce called %d times, want 1 (aborted before the second attempt)", calls)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("syncUntilFullReconcile did not return promptly on ctx cancel")
	}
}
