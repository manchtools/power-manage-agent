package handler

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/agent/internal/executor"
)

// ctxCapturingOsquery records the context handed to each osquery call so a
// test can prove the request context is propagated rather than dropped to a
// fresh context.Background().
type ctxCapturingOsquery struct {
	lastTableCtx context.Context
}

func (f *ctxCapturingOsquery) Query(_ context.Context, q *pb.OSQuery) (*pb.OSQueryResult, error) {
	return &pb.OSQueryResult{QueryId: q.GetQueryId(), Success: true}, nil
}

func (f *ctxCapturingOsquery) QueryTable(ctx context.Context, _ string) ([]*pb.OSQueryRow, error) {
	f.lastTableCtx = ctx
	return []*pb.OSQueryRow{{Data: map[string]string{"k": "v"}}}, nil
}

type inventoryCtxKey string

// TestSupplementWithOsquery_PropagatesRequestContext proves inventory osquery
// collection honours the caller's context. A signed RequestInventory RPC flows
// OnRequestInventory(ctx) -> CollectInventory(ctx) -> supplementWithOsquery;
// before the fix that last hop dropped the ctx and rooted context.Background()
// for every osquery QueryTable, so the RPC's deadline/cancellation never
// reached osquery. This is the NIS2 / spec-12 "no context.Background() in a
// request path" invariant for the inventory path.
func TestSupplementWithOsquery_PropagatesRequestContext(t *testing.T) {
	h := NewHandler(slog.Default(), executor.NewExecutor(nil, nil), nil, nil, make(chan struct{}, 1))
	oq := &ctxCapturingOsquery{}

	const k inventoryCtxKey = "req-sentinel"
	ctx := context.WithValue(context.Background(), k, "v1")

	h.supplementWithOsquery(ctx, oq, map[string]*pb.InventoryTable{})

	require.NotNil(t, oq.lastTableCtx, "osquery QueryTable was never called — the test is vacuous")
	require.Equal(t, "v1", oq.lastTableCtx.Value(k),
		"supplementWithOsquery dropped the caller context (rooted a fresh context.Background()); a cancelled or deadlined RequestInventory RPC would not propagate to osquery")
}
