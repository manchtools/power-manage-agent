// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

func (e *Executor) executeRpm(ctx context.Context, params *pb.AppInstallParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("app params required")
	}

	// Skip on non-rpm systems
	if _, err := exec.LookPath("rpm"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return &pb.CommandOutput{Stdout: "skipped: rpm not available on this system"}, false, nil
		}
		return nil, false, fmt.Errorf("rpm lookup: %w", err)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Repair filesystem if mounted read-only.
		// Done before the download so a remount failure short-circuits
		// the network round-trip on a host that can't accept writes.
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Download to temp file. We need the file in hand before
		// we can ask the package what its real NAME is — the
		// previous shape derived the name by splitting the URL
		// filename on '-', which is wrong for any package whose
		// upstream name itself contains a dash (mypkg-utils-1.2.3.rpm
		// would parse as "mypkg" and the install would silently
		// skip-or-reapply against the wrong package).
		tmpFile, err := os.CreateTemp("", "*.rpm")
		if err != nil {
			return nil, false, fmt.Errorf("create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		_ = tmpFile.Close()

		if err := e.downloadFile(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Ask rpm itself for the canonical package NAME from the
		// downloaded file — authoritative across naming conventions.
		queryOut, _, qErr := queryCmdOutput("rpm", "-qp", "--qf", "%{NAME}", tmpFile.Name())
		if qErr != nil {
			return nil, false, fmt.Errorf("rpm -qp NAME: %w", qErr)
		}
		pkgName := strings.TrimSpace(queryOut)
		if pkgName == "" {
			return nil, false, fmt.Errorf("rpm -qp NAME returned empty for %s", params.Url)
		}

		if e.isRpmInstalled(pkgName) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("rpm package %s is already installed", pkgName),
			}, false, nil
		}

		// Install with rpm (requires sudo)
		output, err := runSudoCmd(ctx, "rpm", "-i", tmpFile.Name())
		return output, true, err

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// For ABSENT the URL is the only handle we have; we must
		// download to learn the real NAME before asking rpm whether
		// it's installed. This is wasteful when the package is
		// already absent, but the alternative (the prior dash-split
		// heuristic) was *unsound* — operator-correctness over
		// network round-trip.
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}
		tmpFile, err := os.CreateTemp("", "*.rpm")
		if err != nil {
			return nil, false, fmt.Errorf("create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		_ = tmpFile.Close()
		if err := e.downloadFile(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}
		queryOut, _, qErr := queryCmdOutput("rpm", "-qp", "--qf", "%{NAME}", tmpFile.Name())
		if qErr != nil {
			return nil, false, fmt.Errorf("rpm -qp NAME: %w", qErr)
		}
		pkgName := strings.TrimSpace(queryOut)
		if pkgName == "" {
			return nil, false, fmt.Errorf("rpm -qp NAME returned empty for %s", params.Url)
		}
		if !e.isRpmInstalled(pkgName) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("rpm package %s is already not installed", pkgName),
			}, false, nil
		}

		output, err := runSudoCmd(ctx, "rpm", "-e", pkgName)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isRpmInstalled checks if an rpm package is installed.
func (e *Executor) isRpmInstalled(pkgName string) bool {
	return checkCmdSuccess("rpm", "-q", pkgName)
}
