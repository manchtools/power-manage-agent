// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"

	sdk "github.com/manchtools/power-manage-sdk"
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

	// Per-manager skip-check BEFORE any validation or remount: if the action
	// carries no config for the host's package manager, it's a no-op and
	// shouldn't trigger validation or a sudo-backed remount on a read-only root.
	// The skip path returns changed=false; remount only fires when there is work.
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

	// Build the repository Manager over the executor's per-instance runner (the
	// same field the reboot path uses), not the process-global executorRunner —
	// so a nil-runner executor fails closed here instead of silently borrowing
	// global state. A nil runner (or, defensively, an unsupported backend the
	// skip switch already filtered) yields the configuration error below.
	mgr, err := repo.New(e.pkgBackend, e.runner)
	if err != nil {
		return nil, false, fmt.Errorf("no supported package manager found for repository configuration")
	}

	// Validate BEFORE requireWritableFS via the SDK's repo.Manager.Validate — the
	// single source of the per-backend field grammar (name shape + length,
	// URL/baseurl shape, control-char/newline rejection on every field, gpgkey
	// ref). requireWritableFS can invoke a sudo-backed remount on a read-only
	// root, so a malformed action must be rejected up front; a field-only
	// Repository is validated (no GPG-key download) so this stays a cheap,
	// network-free gate. apt's gpg_key_url is the agent's own field — validated in
	// downloadAptKey via sdk.ValidateHTTPSURL.
	if err := mgr.Validate(e.repositoryFields(params)); err != nil {
		return nil, false, err
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

// repositoryFields maps the proto request to the SDK repo.Repository for the
// host's package manager WITHOUT resolving the apt signing key (no network).
// Used for the pre-flight repo.Manager.Validate gate; the PRESENT path then
// resolves the key via repositoryConfig before Apply.
func (e *Executor) repositoryFields(params *pb.RepositoryParams) repo.Repository {
	r := repo.Repository{Name: params.Name}
	switch e.pkgBackend {
	case pkg.Apt:
		a := params.Apt
		r.Apt = &repo.AptConfig{
			URL:          a.Url,
			Distribution: a.Distribution,
			Components:   a.Components,
			Arch:         a.Arch,
			Trusted:      a.Trusted,
		}
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
	return r
}

// repositoryConfig builds the full SDK repo.Repository, resolving the apt signing
// key into bytes (the SDK dearmors and installs it): either downloaded from
// gpg_key_url or taken from the inline gpg_key field. The non-apt backends pass
// the GPG key as a reference string (the SDK imports it with `rpm --import`).
func (e *Executor) repositoryConfig(ctx context.Context, params *pb.RepositoryParams) (repo.Repository, error) {
	r := e.repositoryFields(params)
	if e.pkgBackend == pkg.Apt && r.Apt != nil {
		switch a := params.Apt; {
		case a.GpgKeyUrl != "":
			key, err := e.downloadAptKey(ctx, a.GpgKeyUrl)
			if err != nil {
				return repo.Repository{}, err
			}
			r.Apt.GPGKey = key
		case a.GpgKey != "":
			r.Apt.GPGKey = []byte(a.GpgKey)
		}
	}
	return r, nil
}

// downloadAptKey fetches the apt signing key from an https URL. The SDK
// dearmors and installs the returned bytes; the agent owns the download because
// the network policy (proxy, TLS pinning, rate) is the caller's concern. The
// scheme is restricted to https (WS7) and the body is bounded to 10 MiB.
func (e *Executor) downloadAptKey(ctx context.Context, keyURL string) ([]byte, error) {
	if err := sdk.ValidateHTTPSURL(keyURL); err != nil {
		return nil, fmt.Errorf("GPG key URL rejected: %w", err)
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
	// Read one byte past the cap so an oversized key is REJECTED rather than
	// silently truncated: io.ReadAll(io.LimitReader(r, n)) returns only the
	// first n bytes with no error, which would hand a corrupt (truncated) key to
	// gpg --dearmor and surface as a confusing dearmor failure later.
	const maxGPGKeySize = 10 << 20 // 10 MiB
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGPGKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read GPG key response: %w", err)
	}
	if len(raw) > maxGPGKeySize {
		return nil, fmt.Errorf("GPG key exceeds the %d-byte limit", maxGPGKeySize)
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
