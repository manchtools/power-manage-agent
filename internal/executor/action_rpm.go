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
	"github.com/manchtools/power-manage/sdk/go/pkg"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

func (e *Executor) executeRpm(ctx context.Context, params *pb.AppInstallParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("app params required")
	}

	// Fail closed before any privileged remount or network round-trip:
	// the artifact URL must be https and carry a checksum. The control
	// plane already mandates both; this is the executor-boundary defense
	// in depth (WS8 finding 1). Runs before the rpm lookup so a malformed
	// action is rejected on every host, not silently skipped.
	if err := requireVerifiedArtifact(params.Url, params.ChecksumSha256); err != nil {
		return nil, false, err
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
		// downloaded file — authoritative across naming conventions —
		// and validate it: a crafted .rpm can set %{NAME} to a
		// flag-shaped or metacharacter-bearing value.
		pkgName, err := rpmPackageName(queryCmdOutput, tmpFile.Name())
		if err != nil {
			return nil, false, err
		}

		if e.isRpmInstalled(pkgName) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("rpm package %s is already installed", pkgName),
			}, false, nil
		}

		// Install with rpm (requires sudo). The path is a temp file we
		// created, but pass it after `--` for consistency with the rest
		// of the rpm argv discipline.
		output, err := runSudoCmd(ctx, "rpm", "-i", "--", tmpFile.Name())
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
			// Unlike .deb, an .rpm filename has no reliable name field
			// (the name itself can contain hyphens), so a dead URL leaves
			// us with no way to identify the installed package to remove.
			// Surface that explicitly instead of a bare "download" error.
			return nil, false, fmt.Errorf("cannot determine rpm package to remove: artifact %s is unreachable (%w); re-point the action at a reachable URL or remove the package manually", params.Url, err)
		}
		pkgName, err := rpmPackageName(queryCmdOutput, tmpFile.Name())
		if err != nil {
			return nil, false, err
		}
		if !e.isRpmInstalled(pkgName) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("rpm package %s is already not installed", pkgName),
			}, false, nil
		}

		output, err := runSudoCmd(ctx, "rpm", rpmEraseArgs(pkgName)...)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isRpmInstalled checks if an rpm package is installed.
func (e *Executor) isRpmInstalled(pkgName string) bool {
	return checkCmdSuccess("rpm", rpmQueryArgs(pkgName)...)
}

// rpmQueryFunc matches queryCmdOutput's signature; injectable so tests
// can supply a crafted %{NAME} without a real rpm binary or .rpm file.
type rpmQueryFunc func(name string, args ...string) (string, int, error)

// rpmPackageName asks rpm for the canonical %{NAME} of the .rpm at path
// and validates it. The name a (possibly crafted) .rpm reports is
// untrusted input, so it MUST pass pkg.ValidateRpmPackageName before it
// can reach `rpm -q`/`rpm -e` argv — parity with the deb-side
// validDebPkgName check. An empty/whitespace name is rejected by the
// validator (no separate empty check needed).
func rpmPackageName(queryFn rpmQueryFunc, path string) (string, error) {
	out, _, err := queryFn("rpm", "-qp", "--qf", "%{NAME}", path)
	if err != nil {
		return "", fmt.Errorf("rpm -qp NAME: %w", err)
	}
	name := strings.TrimSpace(out)
	if err := pkg.ValidateRpmPackageName(name); err != nil {
		return "", fmt.Errorf("rpm reported an unsafe package name: %w", err)
	}
	return name, nil
}

// rpmQueryArgs / rpmEraseArgs build rpm argv with the package NAME passed
// after a `--` end-of-options separator, so a name that slipped past
// validation (or a future caller that skips it) can still never be
// reparsed as an rpm option.
func rpmQueryArgs(name string) []string { return sysexec.SeparatePositionals([]string{"-q"}, name) }
func rpmEraseArgs(name string) []string { return sysexec.SeparatePositionals([]string{"-e"}, name) }

// requireVerifiedArtifact fails closed unless rawURL is https and a
// non-empty checksum is present. A download-and-install artifact whose
// only authenticity is TLS to a possibly-compromised origin — or which
// carries no checksum at all — must never be installed. The control
// plane mandates both (proto + server validation); this is the
// agent-side defense in depth at the executor boundary.
func requireVerifiedArtifact(rawURL, checksum string) error {
	if err := validateHTTPS(rawURL); err != nil {
		return fmt.Errorf("artifact rejected: %w", err)
	}
	checksum = strings.TrimSpace(checksum)
	if checksum == "" {
		return fmt.Errorf("artifact rejected: checksum_sha256 is required (refusing to install an unverified binary)")
	}
	// Validate the FORM, not just presence: a sha256 is exactly 64 hex chars.
	// A malformed checksum can never match the downloaded artifact, so reject it
	// up front with a clear message rather than failing late at the post-download
	// compare (WS16 #2 well-formedness).
	if !isHex64(checksum) {
		return fmt.Errorf("artifact rejected: checksum_sha256 must be 64 hexadecimal characters")
	}
	return nil
}

// isHex64 reports whether s is exactly 64 hexadecimal characters (a sha256
// digest), case-insensitively — operators routinely paste uppercase digests.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
