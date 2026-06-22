//go:build integration

package executor

import (
	"context"
	"time"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// checkCmdSuccess runs an unprivileged command and reports whether it exited 0.
// It lives here (not in production cmd.go) because production code detects
// installed packages and user/group existence through the SDK — pkg.Manager and
// sys/user — so the only remaining callers are the tag-gated integration tests,
// which use it to assert real on-host state.
func checkCmdSuccess(name string, args ...string) bool {
	// Bound the probe so a wedged command (e.g. a package manager blocked on a
	// lock) fails the check instead of hanging the whole integration suite.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := executorRunner.Run(ctx, sysexec.Command{Name: name, Args: args})
	return err == nil && r.ExitCode == 0
}
