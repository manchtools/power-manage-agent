// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

	// Extract package name from URL for checking
	filename := filepath.Base(params.Url)
	pkgName := strings.Split(filename, "-")[0]

	// Check if package is already installed
	isInstalled := e.isRpmInstalled(pkgName)

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		if isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("rpm package %s is already installed", pkgName),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Download to temp file
		tmpFile, err := os.CreateTemp("", "*.rpm")
		if err != nil {
			return nil, false, fmt.Errorf("create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		_ = tmpFile.Close()

		if err := e.downloadFile(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Install with rpm (requires sudo)
		output, err := runSudoCmd(ctx, "rpm", "-i", tmpFile.Name())
		return output, true, err

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if !isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("rpm package %s is already not installed", pkgName),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
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
