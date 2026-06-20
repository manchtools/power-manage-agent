// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
	"github.com/manchtools/power-manage-sdk/sys/repo"
)

// executeRepository configures an external package repository by delegating to
// the SDK repo.Manager, which owns the per-backend file format (apt deb822
// .sources + keyrings, dnf .repo, pacman.conf sections, zypper addrepo), GPG
// key import, idempotency comparison, and post-configuration metadata refresh.
//
// The agent retains three responsibilities the Manager cannot: validating the
// proto request BEFORE any privileged side effect (so a malformed action never
// triggers a sudo-backed remount), detecting whether the action targets THIS
// host's package manager (a no-op skip), and downloading the apt signing key
// from gpg_key_url (the SDK takes key bytes; the network policy is the caller's).
func (e *Executor) executeRepository(ctx context.Context, params *pb.RepositoryParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("repository params required")
	}

	if params.Name == "" {
		return nil, false, fmt.Errorf("repository name required")
	}

	// Validate BEFORE requireWritableFS: requireWritableFS can invoke a
	// sudo-backed remount/repair on a read-only root, so dispatching it for a
	// malformed action (invalid name, oversized name, newline injection in a
	// URL/GPG field, etc.) leaks privileged side-effects the action should have
	// been rejected for up front. Keep validation cheap and before any system
	// mutation. The Manager re-validates internally regardless.
	if !validRepoName.MatchString(params.Name) {
		return nil, false, fmt.Errorf("invalid repository name: must match [a-zA-Z0-9][a-zA-Z0-9._-]*")
	}
	if len(params.Name) > 128 {
		return nil, false, fmt.Errorf("repository name too long: max 128 characters")
	}
	if err := validateRepositoryParams(params); err != nil {
		return nil, false, err
	}

	// Per-manager skip-check BEFORE requireWritableFS: if the action carries no
	// config for the host's package manager, it's a no-op and shouldn't trigger
	// a sudo-backed remount on a read-only root just to bail out. The skip path
	// returns changed=false; remount only fires when there is work to do.
	switch e.pkgBackend {
	case pkg.Apt:
		if params.Apt == nil || params.Apt.Disabled {
			return &pb.CommandOutput{ExitCode: 0, Stdout: "skipped: no APT repository configuration provided"}, false, nil
		}
	case pkg.Dnf:
		if params.Dnf == nil || params.Dnf.Disabled {
			return &pb.CommandOutput{ExitCode: 0, Stdout: "skipped: no DNF repository configuration provided"}, false, nil
		}
	case pkg.Pacman:
		if params.Pacman == nil || params.Pacman.Disabled {
			return &pb.CommandOutput{ExitCode: 0, Stdout: "skipped: no Pacman repository configuration provided"}, false, nil
		}
	case pkg.Zypper:
		if params.Zypper == nil || params.Zypper.Disabled {
			return &pb.CommandOutput{ExitCode: 0, Stdout: "skipped: no Zypper repository configuration provided"}, false, nil
		}
	default:
		return nil, false, fmt.Errorf("no supported package manager found for repository configuration")
	}

	mgr, err := repo.New(e.pkgBackend, executorRunner)
	if err != nil {
		// The skip switch above already rejected unsupported managers; a failure
		// here means a nil runner, which is a configuration error.
		return nil, false, fmt.Errorf("no supported package manager found for repository configuration")
	}

	// Repair filesystem if mounted read-only. Only reached once we know there is
	// actual work to do for THIS host's package manager.
	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, err
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		outcome, rerr := mgr.Remove(ctx, params.Name)
		return repoOutcome(outcome, rerr)
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		r, berr := e.repositoryConfig(ctx, params)
		if berr != nil {
			return nil, false, berr
		}
		outcome, rerr := mgr.Apply(ctx, r)
		return repoOutcome(outcome, rerr)
	default:
		return nil, false, fmt.Errorf("unknown desired state: %v", state)
	}
}

// repositoryConfig maps the proto request to the SDK repo.Repository for the
// host's package manager. For apt it resolves the signing key into bytes (the
// SDK dearmors and installs it): either downloaded from gpg_key_url or taken
// from the inline gpg_key field. The non-apt backends pass the GPG key as a
// reference string (the SDK imports it with `rpm --import`).
func (e *Executor) repositoryConfig(ctx context.Context, params *pb.RepositoryParams) (repo.Repository, error) {
	r := repo.Repository{Name: params.Name}
	switch e.pkgBackend {
	case pkg.Apt:
		a := params.Apt
		cfg := &repo.AptConfig{
			URL:          a.Url,
			Distribution: a.Distribution,
			Components:   a.Components,
			Arch:         a.Arch,
			Trusted:      a.Trusted,
		}
		switch {
		case a.GpgKeyUrl != "":
			key, err := e.downloadAptKey(ctx, a.GpgKeyUrl)
			if err != nil {
				return repo.Repository{}, err
			}
			cfg.GPGKey = key
		case a.GpgKey != "":
			cfg.GPGKey = []byte(a.GpgKey)
		}
		r.Apt = cfg
	case pkg.Dnf:
		d := params.Dnf
		r.Dnf = &repo.DnfConfig{
			BaseURL:        d.Baseurl,
			Description:    d.Description,
			Enabled:        d.Enabled,
			GPGCheck:       d.Gpgcheck,
			GPGKey:         d.Gpgkey,
			ModuleHotfixes: d.ModuleHotfixes,
		}
	case pkg.Pacman:
		p := params.Pacman
		r.Pacman = &repo.PacmanConfig{
			Server:   p.Server,
			SigLevel: p.SigLevel,
		}
	case pkg.Zypper:
		z := params.Zypper
		r.Zypper = &repo.ZypperConfig{
			URL:         z.Url,
			Description: z.Description,
			Enabled:     z.Enabled,
			Autorefresh: z.Autorefresh,
			GPGCheck:    z.Gpgcheck,
			GPGKey:      z.Gpgkey,
			Type:        z.Type,
		}
	}
	return r, nil
}

// downloadAptKey fetches the apt signing key from an https URL. The SDK
// dearmors and installs the returned bytes; the agent owns the download because
// the network policy (proxy, TLS pinning, rate) is the caller's concern. The
// scheme is restricted to https (WS7) and the body is bounded to 10 MiB.
func (e *Executor) downloadAptKey(ctx context.Context, keyURL string) ([]byte, error) {
	if !strings.HasPrefix(keyURL, "https://") {
		return nil, fmt.Errorf("GPG key URL must use https:// scheme, got: %s", keyURL)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", keyURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GPG key request: %w", err)
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download GPG key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GPG key download failed: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MiB limit
	if err != nil {
		return nil, fmt.Errorf("failed to read GPG key response: %w", err)
	}
	return raw, nil
}

// repoOutcome converts an SDK repo.Outcome into the executor's
// (CommandOutput, changed, error) triple. On error the command output is still
// returned so the operator sees the steps that ran (and any stderr) before the
// failure; changed is false on error.
func repoOutcome(o repo.Outcome, err error) (*pb.CommandOutput, bool, error) {
	out := &pb.CommandOutput{
		ExitCode: int32(o.Result.ExitCode),
		Stdout:   o.Result.Stdout,
		Stderr:   o.Result.Stderr,
	}
	if err != nil {
		return out, false, err
	}
	return out, o.Changed, nil
}
