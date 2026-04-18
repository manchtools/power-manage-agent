// Package setup provides agent installation helpers including sudoers configuration.
package setup

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"text/template"
	"time"

	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// validUsername matches safe Unix usernames (lowercase, digits, underscore, dash).
var validUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

//go:embed sudoers.tmpl
var sudoersTmpl string

// SudoersData holds template data for rendering the sudoers file.
type SudoersData struct {
	User string
}

// InstallSudoers renders the embedded sudoers template and installs it to
// /etc/sudoers.d/<user>. The file is validated with visudo before installation.
// Must be run as root.
func InstallSudoers(user string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root")
	}

	if user == "" {
		return fmt.Errorf("user name is required")
	}
	if !validUsername.MatchString(user) {
		return fmt.Errorf("invalid user name: must match [a-z_][a-z0-9_-]*")
	}

	tmpl, err := template.New("sudoers").Parse(sudoersTmpl)
	if err != nil {
		return fmt.Errorf("parse sudoers template: %w", err)
	}

	dest := fmt.Sprintf("/etc/sudoers.d/%s", user)
	tmpFile := dest + ".tmp"

	// Render template to temp file
	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0440)
	if err != nil {
		return fmt.Errorf("create temp sudoers file: %w", err)
	}

	if err := tmpl.Execute(f, SudoersData{User: user}); err != nil {
		_ = f.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("render sudoers template: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("close temp sudoers file: %w", err)
	}

	// Short deadline on these: visudo/chown are millisecond-scale but
	// should never hang if something is wrong with the host.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Validate syntax with visudo
	if result, err := sysexec.Run(ctx, "visudo", "-c", "-f", tmpFile); err != nil {
		os.Remove(tmpFile)
		if result != nil && result.Stderr != "" {
			return fmt.Errorf("sudoers validation failed: %w: %s", err, result.Stderr)
		}
		return fmt.Errorf("sudoers validation failed: %w", err)
	}

	// Atomically move into place
	if err := os.Rename(tmpFile, dest); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("install sudoers file: %w", err)
	}

	// Ensure correct ownership
	if result, err := sysexec.Run(ctx, "chown", "root:root", dest); err != nil {
		if result != nil && result.Stderr != "" {
			return fmt.Errorf("set sudoers ownership: %w: %s", err, result.Stderr)
		}
		return fmt.Errorf("set sudoers ownership: %w", err)
	}

	return nil
}
