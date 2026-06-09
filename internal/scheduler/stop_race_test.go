package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Stop() must halt the Start loop on its own, without relying on the
// context being cancelled, and must do so without a data race on
// stopCh. The F020 fix wrote `s.stopCh = nil` under the lock while
// Start's select read s.stopCh WITHOUT the lock — an unsynchronized
// read/write the race detector flags, and a window where the select
// could re-read nil and miss the close. Run with -race to exercise it.
func TestScheduler_StopHaltsLoopWithoutCtxCancel(t *testing.T) {
	s, _ := newTestScheduler(t)

	// A non-cancellable context: only Stop() can end the loop here.
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		s.Start(ctx)
		close(done)
	}()

	isRunning := func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.running
	}
	// Wait until Start has entered its select loop so Stop() actually
	// races the reader (this is the window the bug lived in).
	require.Eventually(t, isRunning, 2*time.Second, time.Millisecond,
		"scheduler should report running after Start")

	s.Stop()

	select {
	case <-done:
		// Start returned: Stop halted the loop on its own.
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not halt the Start loop without ctx cancellation")
	}
}

// Stop must be safe to call before Start and multiple times — both
// no-op without panicking (F020).
func TestScheduler_StopIdempotentAndPreStartSafe(t *testing.T) {
	s, _ := newTestScheduler(t)

	require.NotPanics(t, s.Stop, "Stop before Start must not panic")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)
	require.Eventually(t, func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.running
	}, 2*time.Second, time.Millisecond)

	require.NotPanics(t, s.Stop, "first Stop must not panic")
	require.NotPanics(t, s.Stop, "second Stop must not panic (idempotent)")
}
