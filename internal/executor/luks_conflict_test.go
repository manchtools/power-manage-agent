package executor

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/agent/internal/store"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// fakeActionStore returns a fixed set of stored actions for conflict
// resolution tests.
type fakeActionStore struct {
	actions []*store.StoredAction
	err     error
}

func (f *fakeActionStore) GetStoredActions() ([]*store.StoredAction, error) {
	return f.actions, f.err
}

func encAction(id string, minWords int32, complexity pb.LpsPasswordComplexity, state pb.DesiredState, assignedAt time.Time) *store.StoredAction {
	return &store.StoredAction{
		ID:         id,
		AssignedAt: assignedAt,
		Action: &pb.Action{
			Type:         pb.ActionType_ACTION_TYPE_ENCRYPTION,
			DesiredState: state,
			Params: &pb.Action_Encryption{Encryption: &pb.EncryptionParams{
				MinWords:                 minWords,
				UserPassphraseComplexity: complexity,
			}},
		},
	}
}

// WS6 #7: resolveLuksConflict picks the winner deterministically:
// highest min_words → highest complexity → oldest assignment. A weaker
// policy must NEVER win, and ABSENT / non-ENCRYPTION actions are excluded.
func TestResolveLuksConflict_WinnerSelection(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	none := pb.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_UNSPECIFIED
	complex := pb.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX
	present := pb.DesiredState_DESIRED_STATE_PRESENT
	absent := pb.DesiredState_DESIRED_STATE_ABSENT

	newExec := func(actions []*store.StoredAction) *Executor {
		e := &Executor{logger: slog.Default(), now: time.Now}
		e.SetActionStore(&fakeActionStore{actions: actions})
		return e
	}

	t.Run("highest min_words wins", func(t *testing.T) {
		e := newExec([]*store.StoredAction{
			encAction("weak", 3, none, present, t0),
			encAction("strong", 7, none, present, t0),
		})
		winner, err := e.resolveLuksConflict("weak")
		require.NoError(t, err)
		assert.Equal(t, "strong", winner, "the stronger min_words policy must win")
	})

	t.Run("complexity breaks a min_words tie", func(t *testing.T) {
		e := newExec([]*store.StoredAction{
			encAction("plain", 5, none, present, t0),
			encAction("complex", 5, complex, present, t0),
		})
		winner, err := e.resolveLuksConflict("plain")
		require.NoError(t, err)
		assert.Equal(t, "complex", winner)
	})

	t.Run("oldest assignment breaks a full tie", func(t *testing.T) {
		e := newExec([]*store.StoredAction{
			encAction("newer", 5, complex, present, t0.Add(time.Hour)),
			encAction("older", 5, complex, present, t0),
		})
		winner, err := e.resolveLuksConflict("newer")
		require.NoError(t, err)
		assert.Equal(t, "older", winner, "oldest assignment wins on a full tie")
	})

	t.Run("ABSENT and non-encryption excluded", func(t *testing.T) {
		strongAbsent := encAction("strong-absent", 9, complex, absent, t0)
		pkg := &store.StoredAction{
			ID:         "pkg",
			AssignedAt: t0,
			Action:     &pb.Action{Type: pb.ActionType_ACTION_TYPE_PACKAGE, DesiredState: present},
		}
		e := newExec([]*store.StoredAction{
			encAction("live", 4, none, present, t0),
			strongAbsent,
			pkg,
		})
		// Only one live ENCRYPTION candidate → it wins despite the
		// stronger ABSENT one being present.
		winner, err := e.resolveLuksConflict("live")
		require.NoError(t, err)
		assert.Equal(t, "live", winner)
	})

	t.Run("single candidate returns itself", func(t *testing.T) {
		e := newExec([]*store.StoredAction{encAction("solo", 5, none, present, t0)})
		winner, err := e.resolveLuksConflict("solo")
		require.NoError(t, err)
		assert.Equal(t, "solo", winner)
	})

	t.Run("a weaker policy never wins over a stronger peer", func(t *testing.T) {
		e := newExec([]*store.StoredAction{
			encAction("weak", 3, none, present, t0),
			encAction("mid", 5, none, present, t0),
			encAction("strong", 8, complex, present, t0),
		})
		// Even when THIS action is the strong one, query as the weak one:
		// the winner must be the strongest, never the caller by default.
		winner, err := e.resolveLuksConflict("weak")
		require.NoError(t, err)
		assert.Equal(t, "strong", winner)
	})
}
