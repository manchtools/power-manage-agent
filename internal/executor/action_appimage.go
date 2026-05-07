// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage/sdk/go/sys/fs"
)

func (e *Executor) executeAppImage(ctx context.Context, params *pb.AppInstallParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("app params required")
	}

	installPath := params.InstallPath
	if installPath == "" {
		installPath = "/opt/appimages"
	}

	filename := filepath.Base(params.Url)
	fullPath := filepath.Join(installPath, filename)

	// Resolve symlinks to prevent traversal attacks
	resolvedPath, err := sysfs.ResolveAndValidatePath(fullPath)
	if err != nil {
		return nil, false, fmt.Errorf("invalid path: %w", err)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Check if file already exists with correct checksum
		if params.ChecksumSha256 != "" {
			if content, err := os.ReadFile(resolvedPath); err == nil {
				h := sha256.Sum256(content)
				actualHash := hex.EncodeToString(h[:])
				if actualHash == params.ChecksumSha256 {
					return &pb.CommandOutput{
						ExitCode: 0,
						Stdout:   fmt.Sprintf("appimage %s already installed with correct checksum", filename),
					}, false, nil
				}
			}
		} else if _, err := os.Stat(resolvedPath); err == nil {
			// No checksum specified, file exists
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("appimage %s already installed", filename),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Create directory
		if err := os.MkdirAll(filepath.Dir(resolvedPath), 0755); err != nil {
			return nil, false, fmt.Errorf("create directory: %w", err)
		}

		// Download file
		if err := e.downloadFile(ctx, params.Url, resolvedPath, params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Make executable
		if err := os.Chmod(resolvedPath, 0755); err != nil {
			return nil, false, fmt.Errorf("chmod: %w", err)
		}

		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("installed %s to %s", filename, resolvedPath),
		}, true, nil

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Check if file already doesn't exist
		if _, err := os.Stat(resolvedPath); os.IsNotExist(err) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("appimage %s already not present", filename),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		if err := os.Remove(resolvedPath); err != nil {
			return nil, false, fmt.Errorf("remove: %w", err)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("removed %s", resolvedPath),
		}, true, nil
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}
