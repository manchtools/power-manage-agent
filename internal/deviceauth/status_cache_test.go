package deviceauth

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/agent/internal/credentials"
)

// countingStore counts Load() calls so the test can prove the costly
// Argon2id-bearing Load is not run per request.
type countingStore struct {
	exists bool
	loads  atomic.Int64
}

func (c *countingStore) Exists() bool { return c.exists }
func (c *countingStore) Load() (*credentials.Credentials, error) {
	c.loads.Add(1)
	return &credentials.Credentials{DeviceID: "dev-cached"}, nil
}
func (c *countingStore) Save(*credentials.Credentials) error { return nil }

func newStatusHandler(store credentialStore) *EnrollHandler {
	return &EnrollHandler{credStore: store, logger: slog.Default(), now: time.Now}
}

// flakyStore is a credentialStore whose Load result is controllable, so a test
// can exercise the "credentials exist but Load fails" path.
type flakyStore struct {
	exists bool
	creds  *credentials.Credentials
	err    error
}

func (f *flakyStore) Exists() bool                            { return f.exists }
func (f *flakyStore) Load() (*credentials.Credentials, error) { return f.creds, f.err }
func (f *flakyStore) Save(*credentials.Credentials) error     { return nil }

// TestGetEnrollmentStatus_LoadFailureNotCached pins WS9 #7: when credentials
// EXIST but Load fails (a transient decrypt/IO error), status reports
// not-enrolled and does NOT cache that result — so a later successful Load is
// still observed as enrolled. A cached failure would pin "not enrolled" for the
// whole process lifetime after one transient blip.
func TestGetEnrollmentStatus_LoadFailureNotCached(t *testing.T) {
	store := &flakyStore{exists: true, err: errors.New("decrypt failed")}
	h := newStatusHandler(store)

	resp, err := h.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Enrolled, "a load failure must report not-enrolled")

	// Recover: once Load succeeds the status must flip — proving the failure was
	// not cached.
	store.err = nil
	store.creds = &credentials.Credentials{DeviceID: "dev-recovered"}
	resp, err = h.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Enrolled, "a transient load failure must not be cached as not-enrolled")
	assert.Equal(t, "dev-recovered", resp.Msg.DeviceId)
}

// GetEnrollmentStatus must not run credStore.Load() (a 64 MiB Argon2id
// derivation) more than once across many calls — the socket is 0666, so
// per-call derivation is a local DoS.
func TestGetEnrollmentStatus_LoadsAtMostOnce(t *testing.T) {
	store := &countingStore{exists: true}
	h := newStatusHandler(store)

	for i := 0; i < 50; i++ {
		resp, err := h.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
		require.NoError(t, err)
		assert.True(t, resp.Msg.Enrolled)
		assert.Equal(t, "dev-cached", resp.Msg.DeviceId)
	}
	assert.LessOrEqual(t, store.loads.Load(), int64(1),
		"Load (Argon2id) must run at most once across repeated status calls; got %d", store.loads.Load())
}

// A concurrent flood must also collapse to a single Load — the cache +
// statusMu must serialize the first derivation, not let N goroutines all
// derive before the cache is populated.
func TestGetEnrollmentStatus_ConcurrentFloodLoadsOnce(t *testing.T) {
	store := &countingStore{exists: true}
	h := newStatusHandler(store)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(1), store.loads.Load(),
		"a concurrent status flood must trigger exactly one Argon2id derivation")
}

// When not enrolled, Load must never run (Exists() is a cheap stat).
func TestGetEnrollmentStatus_NotEnrolledNeverLoads(t *testing.T) {
	store := &countingStore{exists: false}
	h := newStatusHandler(store)

	resp, err := h.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Enrolled)
	assert.Equal(t, int64(0), store.loads.Load(), "un-enrolled status must not derive the key")
}
