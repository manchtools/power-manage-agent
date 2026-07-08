package executor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// TestRecordLuksTimestampFailure_EscalatesAtThreshold pins the
// Warn→Error escalation contract for #80: a single
// SetLuksLastRotatedAt failure must log at Warn so Bundle A's
// silent-discard regression doesn't return; the threshold-th and
// later consecutive failures escalate to Error so journald-priority
// filters surface what would otherwise be a buried hot-loop or
// stuck-rotation hazard.
func TestRecordLuksTimestampFailure_EscalatesAtThreshold(t *testing.T) {
	var buf bytes.Buffer
	e := &Executor{logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), now: time.Now}

	const actionID = "01HXTEST0000000000000ABCDE"
	for i := 1; i <= luksTimestampFailureThreshold+1; i++ {
		e.recordLuksTimestampFailure(actionID, "post_rotation", errors.New("disk full"))
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if got, want := len(lines), luksTimestampFailureThreshold+1; got != want {
		t.Fatalf("expected %d log lines, got %d:\n%s", want, got, buf.String())
	}

	for i, line := range lines {
		switch {
		case i < luksTimestampFailureThreshold-1:
			// First (threshold-1) failures must be Warn — staying
			// at Error from the first failure would page operators
			// for transient single-tick blips.
			if !strings.Contains(line, "level=WARN") {
				t.Errorf("line %d (consecutive=%d) expected WARN, got: %s", i+1, i+1, line)
			}
			if !strings.Contains(line, "consecutive_failures="+itoa(i+1)) {
				t.Errorf("line %d expected consecutive_failures=%d, got: %s", i+1, i+1, line)
			}
		default:
			// Threshold-th failure onward must be Error. The
			// threshold-th line and the (threshold+1)-th line both
			// fall in this branch — the escalation persists, it
			// doesn't toggle back to Warn.
			if !strings.Contains(line, "level=ERROR") {
				t.Errorf("line %d (consecutive=%d) expected ERROR, got: %s", i+1, i+1, line)
			}
			if !strings.Contains(line, "consecutive_failures="+itoa(i+1)) {
				t.Errorf("line %d expected consecutive_failures=%d, got: %s", i+1, i+1, line)
			}
			if !strings.Contains(line, "rotation may hot-loop") {
				t.Errorf("line %d expected hot-loop hint in error msg, got: %s", i+1, line)
			}
		}
	}
}

// TestClearLuksTimestampFailures_ResetsCounter verifies the success
// path resets the per-action counter, so a recovered failure mode
// doesn't leave the next genuine failure already at Error level.
func TestClearLuksTimestampFailures_ResetsCounter(t *testing.T) {
	var buf bytes.Buffer
	e := &Executor{logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), now: time.Now}

	const actionID = "01HXTEST0000000000000ABCDE"

	// Push the counter past the threshold.
	for i := 1; i <= luksTimestampFailureThreshold; i++ {
		e.recordLuksTimestampFailure(actionID, "post_rotation", errors.New("disk full"))
	}
	// Recover.
	e.clearLuksTimestampFailures(actionID)
	// Reset buf so we only inspect the post-recovery failure.
	buf.Reset()

	// Next failure after a recovery must drop back to Warn — operators
	// shouldn't be paged for a single new failure when the prior streak
	// already resolved.
	e.recordLuksTimestampFailure(actionID, "post_rotation", errors.New("disk full"))
	got := buf.String()
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("expected first post-recovery failure at WARN, got: %s", got)
	}
	if !strings.Contains(got, "consecutive_failures=1") {
		t.Errorf("expected consecutive_failures=1 after recovery, got: %s", got)
	}
}

// TestRecordLuksTimestampFailure_PerActionIsolation guards against
// the obvious shared-counter bug: two actions failing must not
// cross-contaminate each other's escalation state.
func TestRecordLuksTimestampFailure_PerActionIsolation(t *testing.T) {
	var buf bytes.Buffer
	e := &Executor{logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), now: time.Now}

	// Action A fails (threshold-1) times — still at Warn.
	for i := 1; i < luksTimestampFailureThreshold; i++ {
		e.recordLuksTimestampFailure("action-A", "post_rotation", errors.New("disk full"))
	}
	buf.Reset()

	// Action B's first failure must NOT inherit action A's count.
	e.recordLuksTimestampFailure("action-B", "post_rotation", errors.New("disk full"))
	got := buf.String()
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("action-B's first failure must be WARN, not promoted by action-A's streak; got: %s", got)
	}
	if !strings.Contains(got, "consecutive_failures=1") {
		t.Errorf("action-B's first failure must show consecutive_failures=1; got: %s", got)
	}
}

// itoa avoids pulling strconv just for these tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// #173 review finding: when the FIRST rotation timestamp cannot be
// persisted, checkAndRotate returned (false, nil) — every subsequent
// tick re-entered the zero branch and rotation never started, invisibly
// (the #80 escalation only raised the LOG level). It must fail the
// action loudly instead. Driven via a CLOSED store so
// SetLuksLastRotatedAt returns a real error.
func TestCheckAndRotate_InitialTimestampPersistFailure_FailsLoud(t *testing.T) {
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil { // subsequent writes error
		t.Fatal(err)
	}

	e := &Executor{logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), now: time.Now}
	e.SetStore(st)
	e.SetLuksKeyStore(&fakeLuksKeyStore{})

	params := &pb.EncryptionParams{RotationIntervalDays: 30}
	changed, err := e.checkAndRotate(context.Background(), params, &store.LuksState{}, "01HXROTATEFAIL000000000000", "/dev/sda2")
	if err == nil {
		t.Fatal("checkAndRotate must fail loudly when the initial rotation timestamp cannot be persisted — (false, nil) parks rotation forever")
	}
	if changed {
		t.Fatal("no rotation may be reported on the failure path")
	}
	if !strings.Contains(err.Error(), "rotation cannot start") {
		t.Fatalf("error must name the stuck-rotation consequence, got: %v", err)
	}
}
