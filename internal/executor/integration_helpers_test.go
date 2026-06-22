//go:build integration

package executor

import (
	"context"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// checkCmdSuccess runs an unprivileged command and reports whether it exited 0.
// It lives here (not in production cmd.go) because production code detects
// installed packages and user/group existence through the SDK — pkg.Manager and
// sys/user — so the only remaining callers are the tag-gated integration tests,
// which use it to assert real on-host state.
func checkCmdSuccess(name string, args ...string) bool {
	r, err := executorRunner.Run(context.Background(), sysexec.Command{Name: name, Args: args})
	return err == nil && r.ExitCode == 0
}
