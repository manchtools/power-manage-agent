package scheduler

import (
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/manchtools/power-manage/agent/internal/store"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// WS15 #1 — fail-CLOSED on a corrupt persisted maintenance window.
//
// scheduler.New logs a Warn and leaves s.window nil when loadMaintenanceWindow
// returns a decode error, so maintenance.IsAllowed(nil, t) == true and dispatch
// is unconstrained — a tampered/corrupt persisted window UNGATES the agent
// instead of denying it. Design intent: a window that EXISTS but cannot be
// proto-decoded must fail closed (deny-until-next-sync), cleared only by the
// next successful SetMaintenanceWindow. A truly-absent row stays unconstrained
// (the same default a fresh device gets before its first sync).

func TestNew_CorruptPersistedWindow_FailsClosed(t *testing.T) {
	now := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

	t.Run("correct: no persisted row boots unconstrained (allowed)", func(t *testing.T) {
		st := newStore(t)
		s := New(st, &mockExecutor{}, slog.Default())
		s.now = func() time.Time { return now }
		if s.activeWindow() != nil {
			t.Fatalf("fresh store should have a nil window, got %v", s.activeWindow())
		}
		if !s.dispatchAllowed(now) {
			t.Fatal("a never-synced device must allow dispatch (unconstrained default)")
		}
	})

	t.Run("correct: a valid persisted window round-trips and gates", func(t *testing.T) {
		st := newStore(t)
		seed := New(st, &mockExecutor{}, slog.Default())
		// Allow only Saturdays 22:00-06:00 — closed at a Sunday noon.
		w := &pb.MaintenanceWindow{Schedule: []*pb.MaintenanceWindowEntry{
			{Days: []string{"sat"}, Allow: "22:00-06:00"},
		}}
		seed.SetMaintenanceWindow(w)

		restored := New(st, &mockExecutor{}, slog.Default())
		if restored.activeWindow() == nil {
			t.Fatal("valid persisted window must restore")
		}
		// now (2026-06-14) is a Sunday noon → outside the Saturday-night window.
		if restored.dispatchAllowed(now) {
			t.Fatal("valid window must gate dispatch outside its allowed range")
		}
	})

	t.Run("the bug: byte-tampered persisted window fails CLOSED (deny-until-sync)", func(t *testing.T) {
		st := newStore(t)
		// Garbage that proto.Unmarshal rejects — tamper the BYTES so a no-op
		// decode cannot pass. (A trailing 0xff group-end with junk is invalid
		// wire format for MaintenanceWindow.)
		if err := st.SetSetting(maintenanceWindowSettingKey, string([]byte{0xff, 0x00, 0x13, 0x37})); err != nil {
			t.Fatalf("seed corrupt setting: %v", err)
		}
		// Sanity: confirm the bytes really are undecodable, so this test pins
		// the decode-error path and not an empty/no-op decode.
		if err := proto.Unmarshal([]byte{0xff, 0x00, 0x13, 0x37}, &pb.MaintenanceWindow{}); err == nil {
			t.Fatal("test setup invalid: tampered bytes unexpectedly decoded cleanly")
		}

		s := New(st, &mockExecutor{}, slog.Default())
		s.now = func() time.Time { return now }
		// RED today: New leaves s.window nil and dispatchAllowed == true
		// (fail-open). The deny-until-sync sentinel must make this false at
		// EVERY moment until the next sync overwrites the window.
		if s.dispatchAllowed(now) {
			t.Fatal("corrupt persisted window must fail CLOSED (deny dispatch), got allowed")
		}
		if s.dispatchAllowed(now.Add(48 * time.Hour)) {
			t.Fatal("corrupt persisted window must deny at every moment until next sync")
		}
	})

	t.Run("recovery: next sync clears the deny sentinel and restores gating", func(t *testing.T) {
		st := newStore(t)
		if err := st.SetSetting(maintenanceWindowSettingKey, string([]byte{0xff, 0x00, 0x13, 0x37})); err != nil {
			t.Fatalf("seed corrupt setting: %v", err)
		}
		s := New(st, &mockExecutor{}, slog.Default())
		s.now = func() time.Time { return now }
		if s.dispatchAllowed(now) {
			t.Fatal("precondition: corrupt boot must deny")
		}

		// The next successful sync (an empty/cleared window) lifts the deny
		// sentinel — fail-closed is "until next sync", not a permanent brick.
		s.SetMaintenanceWindow(nil)
		if !s.dispatchAllowed(now) {
			t.Fatal("after a clearing sync, dispatch must be allowed again (deny sentinel not cleared)")
		}
	})
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}
