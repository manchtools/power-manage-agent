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

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/pkg"
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

	// Skip on non-deb systems
	if _, err := exec.LookPath("dpkg"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return &pb.CommandOutput{Stdout: "skipped: dpkg not available on this system"}, false, nil
		}
		return nil, false, fmt.Errorf("dpkg lookup: %w", err)
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

		if err := e.downloadFile(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Ask dpkg-deb for the canonical package NAME from the
		// downloaded file — authoritative across naming conventions.
		pkgName, err := debPackageName(tmpFile.Name())
		if err != nil {
			return nil, false, err
		}

		if e.isDebInstalled(pkgName) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("deb package %s is already installed", pkgName),
			}, false, nil
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
		// Resolve the package name to remove. Prefer the AUTHORITATIVE
		// canonical name (download + dpkg-deb), matching the PRESENT
		// path: a package installed under a Package field that differs
		// from the URL filename's name segment must still be found, or
		// flipping the action to ABSENT silently fails to remove it.
		// Fall back to the URL-filename heuristic only when the download
		// fails (artifact deleted upstream after install), so ABSENT
		// still reports "already absent" instead of degrading to a
		// download error.
		pkgName, err := e.debAbsentPackageName(ctx, params)
		if err != nil {
			return nil, false, err
		}
		if !e.isDebInstalled(pkgName) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("deb package %s is already not installed", pkgName),
			}, false, nil
		}
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}
		output, err := runSudoCmd(ctx, "dpkg", "-r", pkgName)
		return output, true, err
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
func (e *Executor) debAbsentPackageName(ctx context.Context, params *pb.AppInstallParams) (string, error) {
	tmpFile, err := os.CreateTemp("", "*.deb")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	_ = tmpFile.Close()

	if dlErr := e.downloadFile(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256); dlErr == nil {
		// Download succeeded — the canonical name is authoritative.
		if name, nameErr := debPackageName(tmpFile.Name()); nameErr == nil {
			return name, nil
		}
		// dpkg-deb parse failure on a downloaded file is unexpected;
		// fall through to the URL heuristic rather than hard-failing.
	}
	// Download failed (dead URL) or the file was unparseable — best
	// effort from the URL filename so a stale-URL ABSENT still converges.
	return debPackageNameFromURL(params.Url)
}

// debPackageName returns the canonical Package field of the given .deb
// file. Uses dpkg-deb so the answer matches what dpkg -i / dpkg -r will
// see, instead of guessing from the URL filename. The returned name is
// validated against the Debian package-name grammar so a maliciously
// crafted .deb cannot inject a value that confuses downstream sudo'd
// dpkg invocations.
func debPackageName(debPath string) (string, error) {
	out, _, err := queryCmdOutput("dpkg-deb", "-f", debPath, "Package")
	if err != nil {
		return "", fmt.Errorf("dpkg-deb -f Package: %w", err)
	}
	name := strings.TrimSpace(out)
	if name == "" {
		return "", fmt.Errorf("dpkg-deb -f Package returned empty for %s", debPath)
	}
	if !validDebPkgName.MatchString(name) {
		return "", fmt.Errorf("invalid debian package name %q in %s", name, debPath)
	}
	return name, nil
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

// isDebInstalled checks if a deb package is installed.
func (e *Executor) isDebInstalled(pkgName string) bool {
	return checkCmdSuccess("dpkg", "-s", pkgName)
}
