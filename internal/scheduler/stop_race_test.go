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

// #173 review finding: Stop() sets running=false and releases the lock
// BEFORE joining <-done, so a Start() racing the drain could allocate
// new channels and run a second loop while the old goroutine was still
// draining. Start must join the previous loop's done channel first.
// Simulated deterministically: an open done channel stands in for a
// still-draining loop; Start must not flip running until it closes.
func TestScheduler_StartJoinsDrainingPredecessor(t *testing.T) {
	s, _ := newTestScheduler(t)

	// UNBUFFERED and never closed: the send below can only complete
	// while Start's `<-prev` join is actively receiving — a
	// deterministic proof the goroutine reached the join instead of
	// running a second loop (CR catch: a timing window could
	// false-pass if the goroutine simply wasn't scheduled).
	draining := make(chan struct{})
	s.mu.Lock()
	s.running = false
	s.done = draining
	s.mu.Unlock()

	go s.Start(context.Background())

	isRunning := func() bool {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.running
	}

	select {
	case draining <- struct{}{}:
		// Start is parked in the predecessor join — and therefore has
		// NOT started a new loop.
	case <-time.After(2 * time.Second):
		t.Fatal("Start never reached the predecessor join — a racing Start would run a second loop while the old one drains")
	}

	require.Eventually(t, isRunning, 2*time.Second, time.Millisecond,
		"Start should run once the predecessor has fully exited")
	s.Stop()
}
