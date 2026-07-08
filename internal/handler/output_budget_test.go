package handler

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Audit A-02 (issue #170): the streaming callback stops relaying output
// chunks once an execution exhausts its budget, emits exactly ONE
// truncation-marker chunk, and stays silent afterwards — while the
// action itself keeps running (the callback never errors).

func collectChunks() (*[]*pb.OutputChunk, func(*pb.OutputChunk) error, *sync.Mutex) {
	var mu sync.Mutex
	chunks := []*pb.OutputChunk{}
	send := func(c *pb.OutputChunk) error {
		mu.Lock()
		defer mu.Unlock()
		chunks = append(chunks, c)
		return nil
	}
	return &chunks, send, &mu
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestBudgetedChunkCallback_ForwardsUnderBudget(t *testing.T) {
	chunks, send, _ := collectChunks()
	cb := budgetedChunkCallback("exec-1", send, testLogger())

	for i := 0; i < 10; i++ {
		cb(sysexec.StreamStdout, fmt.Sprintf("line %d", i), int64(i))
	}

	require.Len(t, *chunks, 10)
	assert.Equal(t, "exec-1", (*chunks)[0].ExecutionId)
	assert.Equal(t, []byte("line 0"), (*chunks)[0].Data)
	assert.Equal(t, int64(9), (*chunks)[9].Sequence)
}

func TestBudgetedChunkCallback_ByteBudget_OneMarkerThenSilence(t *testing.T) {
	chunks, send, _ := collectChunks()
	cb := budgetedChunkCallback("exec-1", send, testLogger())

	// One line that fills the whole byte budget, then more lines that
	// must all be swallowed behind a single marker.
	big := strings.Repeat("x", maxStreamBytesPerExecution)
	cb(sysexec.StreamStdout, big, 0)
	cb(sysexec.StreamStderr, "over 1", 1)
	cb(sysexec.StreamStdout, "over 2", 2)
	cb(sysexec.StreamStdout, "over 3", 3)

	require.Len(t, *chunks, 2, "big line + exactly one truncation marker")
	marker := (*chunks)[1]
	assert.Contains(t, string(marker.Data), "truncated by agent")
	assert.Equal(t, int64(1), marker.Sequence, "marker replaces the first dropped line")
	assert.Equal(t, pb.OutputStreamType(sysexec.StreamStderr), marker.Stream)
}

func TestBudgetedChunkCallback_ChunkBudget_OneMarkerThenSilence(t *testing.T) {
	chunks, send, _ := collectChunks()
	cb := budgetedChunkCallback("exec-1", send, testLogger())

	for i := 0; i <= maxStreamChunksPerExecution+10; i++ {
		cb(sysexec.StreamStdout, "ln", int64(i))
	}

	require.Len(t, *chunks, maxStreamChunksPerExecution+1, "budgeted chunks + one marker")
	last := (*chunks)[len(*chunks)-1]
	assert.Contains(t, string(last.Data), "truncated by agent")
	for _, c := range (*chunks)[:len(*chunks)-1] {
		assert.NotContains(t, string(c.Data), "truncated", "no premature marker")
	}
}

func TestBudgetedChunkCallback_ConcurrentStreamsSafe(t *testing.T) {
	chunks, send, mu := collectChunks()
	cb := budgetedChunkCallback("exec-1", send, testLogger())

	// stdout + stderr scanners run on separate goroutines in the SDK
	// executor; the budget must be race-free and still emit exactly one
	// marker. Enough volume to blow the byte budget from both sides.
	line := strings.Repeat("y", 64*1024)
	var wg sync.WaitGroup
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(stream sysexec.StreamType) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				cb(stream, line, int64(i))
			}
		}(sysexec.StreamType(g + 1))
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	markers := 0
	for _, c := range *chunks {
		if strings.Contains(string(c.Data), "truncated by agent") {
			markers++
		}
	}
	assert.Equal(t, 1, markers, "exactly one truncation marker under concurrency")
	require.NotEmpty(t, *chunks)
	last := (*chunks)[len(*chunks)-1]
	assert.Contains(t, string(last.Data), "truncated by agent",
		"the marker must be the LAST chunk — no admitted chunk may land after it")
}

func TestBudgetedChunkCallback_NilSendChunkReturnsNil(t *testing.T) {
	assert.Nil(t, budgetedChunkCallback("exec-1", nil, testLogger()),
		"no sink → no callback, matching the prior wiring")
}
