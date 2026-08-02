package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
)

// A compliance-classified action is detection-only. With no detection script
// there is nothing to detect, so the agent must fail closed: the pre-fix
// empty-detection branch ran params.Script instead, executing exactly the
// remediation body the compliance path forbids.
func TestComplianceShellWithoutDetectionScriptFailsClosed(t *testing.T) {
	prev := executorRunner
	t.Cleanup(func() { executorRunner = prev })
	rec := &recordingBaseRunner{}
	executorRunner = rec

	e := NewExecutor(nil)
	execOut, detectionOut, changed, err := e.executeShellStreaming(context.Background(), &pb.ShellParams{
		IsCompliance:    true,
		Script:          "touch /tmp/pm-compliance-remediation-must-never-run",
		DetectionScript: "",
		RunAsRoot:       true,
	}, nil)

	// Asserted before the error so a regression reports BOTH symptoms: the
	// remediation body reaching the runner is the severe half.
	assert.Empty(t, rec.cmds,
		"the compliance path must never dispatch a script when detection is empty")
	require.Error(t, err, "a compliance action without a detection script must fail closed")
	assert.Nil(t, execOut)
	assert.Nil(t, detectionOut)
	assert.False(t, changed)
}

// The accepted compliance shape: detection runs, and only detection. An
// execution script on the same action is reported on, never run.
func TestComplianceShellRunsDetectionOnly(t *testing.T) {
	prev := executorRunner
	t.Cleanup(func() { executorRunner = prev })
	rec := &recordingBaseRunner{}
	executorRunner = rec

	const (
		detection   = "test -f /etc/pm-compliance-probe"
		remediation = "touch /tmp/pm-compliance-remediation-must-never-run"
	)
	e := NewExecutor(nil)
	execOut, detectionOut, changed, err := e.executeShellStreaming(context.Background(), &pb.ShellParams{
		IsCompliance:    true,
		Script:          remediation,
		DetectionScript: detection,
		RunAsRoot:       true,
	}, nil)

	require.NoError(t, err)
	require.Len(t, rec.cmds, 1, "detection runs exactly once and nothing else is dispatched")
	joined := strings.Join(rec.cmds[0].Args, " ")
	assert.Contains(t, joined, detection)
	assert.NotContains(t, joined, remediation,
		"the execution script is never run by the compliance path")
	assert.NotNil(t, detectionOut, "compliance reports its detection findings")
	assert.Nil(t, execOut)
	assert.False(t, changed)
}
