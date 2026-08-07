package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// failingBaseRunner cannot run anything: the interpreter is missing, the
// privilege backend refuses, the binary is not executable.
type failingBaseRunner struct{}

func (failingBaseRunner) Run(_ context.Context, _ sysexec.Command) (sysexec.Result, error) {
	return sysexec.Result{}, errors.New("no such file or directory")
}

func (failingBaseRunner) Stream(_ context.Context, _ sysexec.Command, _ sysexec.OutputCallback) (sysexec.Result, error) {
	return sysexec.Result{}, errors.New("no such file or directory")
}

func (failingBaseRunner) Backend() sysexec.PrivilegeBackend { return sysexec.Direct }

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

// A detection script that could not run at all is not evidence of compliance.
// The reported result is what control stores as the device's compliance state,
// so the compliant flag must stay false however the run failed.
func TestComplianceShellReportsNotCompliantWhenDetectionCannotRun(t *testing.T) {
	prev := executorRunner
	t.Cleanup(func() { executorRunner = prev })
	executorRunner = failingBaseRunner{}

	e := NewExecutor(nil)
	result := e.ExecuteAction(context.Background(), &pb.Action{
		Id:   &pb.ActionId{Value: "01J0000000000000000000000A"},
		Type: pb.ActionType_ACTION_TYPE_SHELL,
		Params: &pb.Action_Shell{Shell: &pb.ShellParams{
			IsCompliance:    true,
			DetectionScript: "test -f /etc/pm-compliance-probe",
			RunAsRoot:       true,
		}},
	})

	assert.False(t, result.Compliant, "a detection script that never ran proves nothing")
	assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, result.Status)
	assert.NotEmpty(t, result.Error)
}
