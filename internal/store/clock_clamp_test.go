package store

import (
	"testing"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// WS15 #5 — forward clock-jump must not suppress drift-prevention beyond one
// interval.
//
// calculateNextExecute / calculateNextExecuteFromSchedule (interval path)
// compute lastExecuted+interval. A future-dated lastExecuted — persisted while
// the wall clock was transiently jumped forward, then corrected back — yields a
// next_execute_at arbitrarily far ahead, so the action silently stops running.
// Intent: the computed cursor must be clamped to min(computed, now+interval) so
// a single forward excursion can delay drift-prevention by at most one
// interval, never indefinitely.

func TestCalculateNextExecute_ForwardClockJump_ClampedToOneInterval(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)
	const intervalHours = 8
	interval := time.Duration(intervalHours) * time.Hour

	newStoreAt := func(t *testing.T) *Store {
		t.Helper()
		st, err := New(t.TempDir())
		if err != nil {
			t.Fatalf("new store: %v", err)
		}
		t.Cleanup(func() { st.Close() })
		st.now = func() time.Time { return now }
		return st
	}

	t.Run("ABSENT/normal: monotonic progression is unchanged", func(t *testing.T) {
		st := newStoreAt(t)
		action := &pb.Action{
			Id:       &pb.ActionId{Value: "01HCLOCKNORMAL00000000000"},
			Type:     pb.ActionType_ACTION_TYPE_SHELL,
			Schedule: &pb.ActionSchedule{IntervalHours: intervalHours},
		}
		last := now.Add(-2 * time.Hour) // executed 2h ago, in the past
		got := st.calculateNextExecute(action, &last, false)
		want := last.UTC().Add(interval)
		if !got.Equal(want) {
			t.Fatalf("normal interval cursor = %v, want %v (unchanged progression)", got, want)
		}
		// And it is at or before now+interval (the clamp ceiling).
		if got.After(now.Add(interval)) {
			t.Fatalf("normal cursor %v exceeds now+interval ceiling %v", got, now.Add(interval))
		}
	})

	t.Run("the bug: future-dated lastExecuted is clamped to now+interval (action)", func(t *testing.T) {
		st := newStoreAt(t)
		action := &pb.Action{
			Id:       &pb.ActionId{Value: "01HCLOCKJUMP000000000000A"},
			Type:     pb.ActionType_ACTION_TYPE_SHELL,
			Schedule: &pb.ActionSchedule{IntervalHours: intervalHours},
		}
		// lastExecuted is 10 days in the FUTURE (a forward clock excursion that
		// has since been corrected back to `now`).
		last := now.Add(240 * time.Hour)
		got := st.calculateNextExecute(action, &last, false)

		ceiling := now.Add(interval)
		// RED today: got == last+interval == now+250h, far past the ceiling.
		if got.After(ceiling) {
			t.Fatalf("future-dated cursor = %v exceeds clamp ceiling now+interval = %v; "+
				"a forward clock jump suppressed drift-prevention beyond one interval", got, ceiling)
		}
	})

	t.Run("the bug: future-dated lastExecuted is clamped (group variant)", func(t *testing.T) {
		schedule := &pb.ActionSchedule{IntervalHours: intervalHours}
		last := now.Add(240 * time.Hour)
		got := calculateNextExecuteFromSchedule(schedule, &last, false, now)

		ceiling := now.Add(interval)
		if got.After(ceiling) {
			t.Fatalf("group future-dated cursor = %v exceeds ceiling %v", got, ceiling)
		}
	})

	t.Run("nil-schedule drift default is also clamped", func(t *testing.T) {
		st := newStoreAt(t)
		action := &pb.Action{
			Id:   &pb.ActionId{Value: "01HCLOCKJUMPNILSCHED00000"},
			Type: pb.ActionType_ACTION_TYPE_SHELL,
			// no Schedule → 8h drift default
		}
		last := now.Add(240 * time.Hour)
		got := st.calculateNextExecute(action, &last, false)
		ceiling := now.Add(8 * time.Hour)
		if got.After(ceiling) {
			t.Fatalf("nil-schedule future-dated cursor = %v exceeds 8h ceiling %v", got, ceiling)
		}
	})
}
