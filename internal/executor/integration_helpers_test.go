//go:build integration

package executor

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// TestMain fail-closes the whole integration suite: these tests mutate real host
// state — create/delete users, write outside the test tree, install packages,
// remount, and (historically) issue a real `shutdown`. They are meant to run
// ONLY inside a disposable container, which is exactly how CI drives them
// (`docker run ... -tags=integration`). Running them on a developer's machine
// has rebooted a workstation. Refuse to run unless we are clearly in a throwaway
// environment, or the operator has explicitly opted in.
func TestMain(m *testing.M) {
	if !disposableHost() {
		fmt.Fprintln(os.Stderr,
			"executor integration tests skipped: not running in a container.\n"+
				"These mutate real host state (users, files, packages). Run them in "+
				"the container lane (`docker run ... -tags=integration`), or set "+
				"PM_ALLOW_DESTRUCTIVE_TESTS=1 to force them on this host.")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// disposableHost reports whether destructive integration tests are safe to run
// here: inside a container (Docker's /.dockerenv or Podman's /run/.containerenv),
// or when the operator explicitly opted in via PM_ALLOW_DESTRUCTIVE_TESTS=1.
func disposableHost() bool {
	if os.Getenv("PM_ALLOW_DESTRUCTIVE_TESTS") == "1" {
		return true
	}
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	return false
}

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
