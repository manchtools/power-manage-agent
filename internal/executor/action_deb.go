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

		// Install with dpkg (requires sudo). On failure, retry via
		// `apt --fix-broken install` which can complete a half-done
		// dpkg invocation. If the retry succeeds, clear the
		// original dpkg error — the action recovered. The previous
		// shape ran FixBroken but propagated the original error
		// regardless, so callers saw "install failed" even when the
		// recovery path resolved it. Verify the final state by
		// re-checking installation rather than trusting either
		// command's exit alone, since FixBroken can succeed without
		// having installed the requested package.
		output, err := runSudoCmd(ctx, "dpkg", "-i", tmpFile.Name())
		if err != nil {
			fbOutput, fbErr := pkg.NewAptWithContext(ctx).FixBroken()
			if fbOutput != nil {
				if output == nil {
					output = &pb.CommandOutput{}
				}
				output.Stdout += "\n=== apt --fix-broken install ===\n" + fbOutput.Stdout
				output.Stderr += fbOutput.Stderr
			}
			if fbErr == nil && e.isDebInstalled(pkgName) {
				err = nil
			}
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
