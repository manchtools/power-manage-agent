package handler

import (
	"log/slog"
	"sync"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"

	"github.com/manchtools/power-manage/agent/internal/executor"
)

// Per-execution streaming budget (audit A-02, issue #170 — the polite
// companion to the server's trust-boundary inbox budget, server#509).
// A well-behaved agent stops relaying OutputChunks once an execution
// has streamed this much, emits exactly ONE truncation-marker chunk,
// and lets the action run to completion. This bounds the per-execution
// OutputChunk event rows on the server without touching the captured
// Result (the SDK's 1 MiB cap) or the local log previews (F-32).
const (
	// maxStreamBytesPerExecution mirrors the SDK's captured-Result cap.
	maxStreamBytesPerExecution = 1 << 20
	// maxStreamChunksPerExecution bounds row count independently of
	// size — a chatty one-byte-per-line action is as unwelcome as a
	// large one.
	maxStreamChunksPerExecution = 4096
)

// truncationMarker is the single final chunk an over-budget execution
// streams; readers of the live output see why it went quiet.
const truncationMarker = "[output truncated by agent: per-execution streaming budget exceeded; the action continues and its captured result is unaffected]"

// budgetedChunkCallback wraps sendChunk in the per-execution budget.
// Returns nil when sendChunk is nil (no streaming sink — matches the
// prior wiring). Safe for concurrent use: the SDK executor pumps
// stdout and stderr from separate goroutines.
func budgetedChunkCallback(executionID string, sendChunk func(*pb.OutputChunk) error, logger *slog.Logger) executor.OutputCallback {
	if sendChunk == nil {
		return nil
	}
	var (
		mu        sync.Mutex
		bytesSent int
		chunks    int
		truncated bool
	)
	return func(streamType sysexec.StreamType, line string, seq int64) {
		mu.Lock()
		if truncated {
			mu.Unlock()
			return
		}
		if bytesSent+len(line) > maxStreamBytesPerExecution || chunks+1 > maxStreamChunksPerExecution {
			truncated = true
			mu.Unlock()
			logger.Info("output streaming budget exceeded; truncating relay (action continues)",
				"execution_id", executionID, "bytes", bytesSent, "chunks", chunks)
			if err := sendChunk(&pb.OutputChunk{
				ExecutionId: executionID,
				Stream:      pb.OutputStreamType(streamType),
				Data:        []byte(truncationMarker),
				Sequence:    seq,
			}); err != nil {
				logger.Warn("failed to send truncation marker chunk", "error", err)
			}
			return
		}
		bytesSent += len(line)
		chunks++
		mu.Unlock()

		if err := sendChunk(&pb.OutputChunk{
			ExecutionId: executionID,
			Stream:      pb.OutputStreamType(streamType),
			Data:        []byte(line),
			Sequence:    seq,
		}); err != nil {
			logger.Warn("failed to send output chunk", "error", err)
		}
	}
}
