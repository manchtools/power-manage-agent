// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
)

// validDebPkgName matches the Debian package-name grammar
// (https://www.debian.org/doc/debian-policy/ch-controlfields.html#source).
// Defence-in-depth: dpkg-deb returns a value parsed out of the .deb
// control file, which an attacker who can publish arbitrary .deb URLs
// could in principle craft. argument-mode exec.Command isn't subject to
// shell injection, but a misnamed package field could still confuse
// downstream tooling, and the grammar is narrow enough that a strict
// regex costs nothing.
var validDebPkgName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)

func (e *Executor) executeDeb(ctx context.Context, params *pb.AppInstallParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("app params required")
	}

	// Fail closed before any privileged remount or network round-trip on the
	// INSTALL path: the artifact URL must be https and carry a checksum.
	// downloadFile enforces https but SKIPS checksum verification when the
	// checksum is empty, so this executor-boundary guard refuses an unverified
	// .deb rather than relying on the proto/server alone (WS16 #2). Only the
	// PRESENT path downloads — ABSENT removes by package name and never fetches
	// the artifact, so it needs no verification (mirrors the AppImage remove
	// path). Runs before the dpkg lookup so a malformed install is rejected
	// even on non-deb hosts.
	if state == pb.DesiredState_DESIRED_STATE_PRESENT {
		if err := requireVerifiedArtifact(params.Url, params.ChecksumSha256); err != nil {
			return nil, false, err
		}
	}

	// Skip on non-deb systems
	if _, err := exec.LookPath("dpkg"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return &pb.CommandOutput{Stdout: "skipped: dpkg not available on this system"}, false, nil
		}
		return nil, false, fmt.Errorf("dpkg lookup: %w", err)
	}

	mgr := e.pkgManagerForCtx(ctx)
	if mgr == nil {
		return nil, false, fmt.Errorf("no usable package manager for .deb (context expired or none detected)")
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Download to temp file. The previous shape derived the
		// package name by splitting the URL filename on "_", which is
		// wrong for any URL whose filename does not follow Debian's
		// `name_version_arch.deb` convention (mirror layouts, custom
		// download proxies, internal artifact stores). Downloading
		// first and asking dpkg-deb for the canonical NAME mirrors
		// the rpm path's authoritative `rpm -qp NAME` query.
		tmpFile, err := os.CreateTemp("", "*.deb")
		if err != nil {
			return nil, false, fmt.Errorf("create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		_ = tmpFile.Close()

		if err := fetchArtifact(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256, ""); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Ask the SDK for the canonical package NAME from the downloaded
		// file (LocalPackageInfo -> dpkg-deb), authoritative across naming
		// conventions and validated against the package-name grammar inside
		// the SDK.
		info, err := mgr.LocalPackageInfo(ctx, tmpFile.Name())
		if err != nil {
			return nil, false, err
		}
		pkgName := info.Name

		if installed, err := mgr.IsInstalled(ctx, pkgName); err != nil {
			return nil, false, fmt.Errorf("check %s installed: %w", pkgName, err)
		} else if installed {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("deb package %s is already installed", pkgName),
			}, false, nil
		}

		// Install through the SDK package manager's local-file install
		// (apt install <path>), which resolves dependencies from the
		// configured repositories AND lets apt set PATH for the dpkg it
		// drives. apt install of a local .deb performs no per-file signature
		// check (deb carries none), so it still honours the agent's
		// checksum-not-gpg artifact model enforced above by
		// requireVerifiedArtifact.
		return packageResult(mgr.InstallLocal(ctx, tmpFile.Name(), pkg.InstallLocalOptions{}))

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Resolve the package name to remove. Prefer the AUTHORITATIVE
		// canonical name (download + dpkg-deb), matching the PRESENT
		// path: a package installed under a Package field that differs
		// from the URL filename's name segment must still be found, or
		// flipping the action to ABSENT silently fails to remove it.
		// Fall back to the URL-filename heuristic only when the download
		// fails (artifact deleted upstream after install), so ABSENT
		// still reports "already absent" instead of degrading to a
		// download error.
		pkgName, err := e.debAbsentPackageName(ctx, mgr, params)
		if err != nil {
			return nil, false, err
		}
		if installed, err := mgr.IsInstalled(ctx, pkgName); err != nil {
			return nil, false, fmt.Errorf("check %s installed: %w", pkgName, err)
		} else if !installed {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("deb package %s is already not installed", pkgName),
			}, false, nil
		}
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}
		// Remove through the SDK manager (apt remove <name>) rather than a
		// direct `dpkg -r`, so the package manager runs the maintainer
		// (prerm) scripts with a proper PATH — the same reason the install
		// path delegates to apt.
		return packageResult(mgr.Remove(ctx, pkg.RemoveOptions{}, pkgName))
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// debAbsentPackageName resolves the package name to remove for an
// ABSENT deb action. It prefers the authoritative canonical Package
// field (download + dpkg-deb), so it agrees with the name the PRESENT
// path installed under even when the URL filename differs. If the
// download fails — the common "artifact deleted upstream after the
// install" case — it falls back to the URL-filename heuristic so the
// action can still report "already absent" rather than erroring.
func (e *Executor) debAbsentPackageName(ctx context.Context, mgr pkg.Manager, params *pb.AppInstallParams) (string, error) {
	tmpFile, err := os.CreateTemp("", "*.deb")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	_ = tmpFile.Close()

	if dlErr := fetchArtifact(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256, ""); dlErr == nil {
		// Download (and checksum) succeeded, so the file is exactly what
		// the action specified. The canonical name is authoritative; a
		// parse failure here is a real corruption/format error, NOT a
		// stale URL — surface it rather than guessing from the URL
		// filename, which could target (and remove) the wrong package.
		info, nameErr := mgr.LocalPackageInfo(ctx, tmpFile.Name())
		if nameErr != nil {
			return "", fmt.Errorf("download succeeded but could not read the package name: %w", nameErr)
		}
		return info.Name, nil
	}
	// Download failed (dead URL — artifact deleted upstream after the
	// install) — best effort from the URL filename so a stale-URL ABSENT
	// still converges to "already absent".
	return debPackageNameFromURL(params.Url)
}

// debPackageNameFromURL parses the canonical Debian package NAME out
// of a .deb URL's filename, expecting the standard
// `<name>_<version>_<arch>.deb` mirror layout. Used by the ABSENT
// path so an action whose URL has 404'd (artifact deleted upstream)
// still reports the desired "already absent" status instead of
// degrading into a download error. The PRESENT path keeps the
// download + dpkg-deb authoritative read because installing requires
// the .deb file anyway.
func debPackageNameFromURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid deb url %q: %w", rawURL, err)
	}
	base := path.Base(parsed.Path)
	if base == "" || base == "/" || base == "." {
		return "", fmt.Errorf("deb url %q has no filename segment", rawURL)
	}
	if !strings.HasSuffix(base, ".deb") {
		return "", fmt.Errorf("deb url filename %q does not end in .deb", base)
	}
	// Filename shape is `name_version_arch.deb`; the package name is
	// everything before the first underscore.
	stem := strings.TrimSuffix(base, ".deb")
	name, _, ok := strings.Cut(stem, "_")
	if !ok || name == "" {
		return "", fmt.Errorf("deb url filename %q is not in name_version_arch.deb form", base)
	}
	if !validDebPkgName.MatchString(name) {
		return "", fmt.Errorf("invalid debian package name %q derived from %s", name, rawURL)
	}
	return name, nil
}
