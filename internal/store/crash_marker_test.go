package store

import (
	"context"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// WS15 #4 — in-flight marker before execute, so a crash between Execute and
// RecordExecution does not re-run a non-idempotent action on the next boot.
//
// Today next_execute_at only advances inside RecordExecution, which runs AFTER
// executor.Execute. A crash in between leaves the action due, so the offline
// scheduler re-dispatches it on restart. Intent: persist a started marker that
// advances the due cursor by one interval BEFORE execution, so a crashed
// in-flight action is not blindly re-dispatched within the same interval.
// (Best-effort for non-idempotent actions; idempotent actions are unaffected.)

func TestExecuteAction_InFlightMarker_NoDoubleApplyAcrossRestart(t *testing.T) {
	const intervalHours = 8
	interval := time.Duration(intervalHours) * time.Hour

	// t0 is when the action was first scheduled; tDue is a later "now" at which
	// the action has become due and the scheduler picks it up.
	t0 := time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC)
	tDue := t0.Add(interval + time.Minute) // just past the first cursor → due

	clock := t0
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer st.Close()
	st.now = func() time.Time { return clock }

	action := &pb.Action{
		Id:       &pb.ActionId{Value: "01HCRASHMARKER0000000000A"},
		Type:     pb.ActionType_ACTION_TYPE_SHELL,
		Schedule: &pb.ActionSchedule{IntervalHours: intervalHours},
	}
	if err := st.SaveAction(action); err != nil {
		t.Fatalf("save action: %v", err)
	}

	// Advance the clock so the action is now due.
	clock = tDue
	due, err := st.GetDueActions(context.Background())
	if err != nil {
		t.Fatalf("get due: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("precondition: expected exactly 1 due action, got %d", len(due))
	}

	// The scheduler marks the action started BEFORE invoking the executor.
	if err := st.MarkActionStarted(action.Id.Value); err != nil {
		t.Fatalf("mark started: %v", err)
	}

	// Simulate a CRASH between Execute and RecordExecution: nothing else runs.
	// On the next boot, the scheduler scans for due actions. The in-flight
	// marker must have advanced the cursor so the crashed action is NOT
	// immediately re-dispatched within the same interval.
	dueAfter, err := st.GetDueActions(context.Background())
	if err != nil {
		t.Fatalf("get due after marker: %v", err)
	}
	for _, a := range dueAfter {
		if a.ID == action.Id.Value {
			t.Fatalf("crashed in-flight action is still due after the started marker "+
				"(cursor not advanced) — it would be re-dispatched on restart; next_execute_at=%v now=%v",
				a.NextExecuteAt, clock)
		}
	}

	// The advanced cursor must be bounded to one interval ahead (not arbitrarily
	// far): at most now+interval, so a recovered action resumes its cadence.
	got, err := st.GetAction(action.Id.Value)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	ceiling := clock.Add(interval)
	if got.NextExecuteAt.After(ceiling) {
		t.Fatalf("started marker advanced cursor to %v, beyond one interval ceiling %v",
			got.NextExecuteAt, ceiling)
	}
}
