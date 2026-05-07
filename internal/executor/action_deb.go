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
	"github.com/manchtools/power-manage/sdk/go/pkg"
)

func (e *Executor) executeDeb(ctx context.Context, params *pb.AppInstallParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("app params required")
	}

	// Skip on non-deb systems
	if _, err := exec.LookPath("dpkg"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return &pb.CommandOutput{Stdout: "skipped: dpkg not available on this system"}, false, nil
		}
		return nil, false, fmt.Errorf("dpkg lookup: %w", err)
	}

	// Extract package name from URL for checking
	filename := filepath.Base(params.Url)
	pkgName := strings.Split(filename, "_")[0]

	// Check if package is already installed
	isInstalled := e.isDebInstalled(pkgName)

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		if isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("deb package %s is already installed", pkgName),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Download to temp file
		tmpFile, err := os.CreateTemp("", "*.deb")
		if err != nil {
			return nil, false, fmt.Errorf("create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		_ = tmpFile.Close()

		if err := e.downloadFile(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Install with dpkg (requires sudo)
		output, err := runSudoCmd(ctx, "dpkg", "-i", tmpFile.Name())
		if err != nil {
			// Try to fix dependencies
			pkg.NewAptWithContext(ctx).FixBroken()
		}
		return output, true, err

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if !isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("deb package %s is already not installed", pkgName),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		output, err := runSudoCmd(ctx, "dpkg", "-r", pkgName)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isDebInstalled checks if a deb package is installed.
func (e *Executor) isDebInstalled(pkgName string) bool {
	return checkCmdSuccess("dpkg", "-s", pkgName)
}
