# Contributing to the Power Manage Agent

The agent runs as root on managed devices and delegates OS work to the [SDK](https://github.com/manchtools/power-manage-sdk) (`sys/*`, `pkg`, `verify`) — the agent must not reimplement OS features the SDK provides. Shared idioms, branch naming, and commit conventions are the SDK's: see its [CONTRIBUTING](https://github.com/manchtools/power-manage-sdk/blob/main/CONTRIBUTING.md). Use an issue first; branch as `<prefix>/issue-<number>-<short-description>`.

## Test tiers

| Tier | Selector | Where it runs |
|---|---|---|
| Unit + arch | `go test -race ./...` (no tags) | host, every PR (`unit-test.yml`) |
| Integration | `//go:build integration` files, functions named `TestIntegration_*` | 4-distro container matrix (`integration-test.yml`) |
| Privileged edge | same tag, functions named `TestEdgeCase_*` | privileged container lane |

Rules the CI enforces (self-discovering guards in `internal/archtest/`):
- Every integration-tagged test must live in a package the workflow tests **and** match a `-run` selector (`TestIntegration_*` / `TestEdgeCase_*`) — anything else never runs anywhere and the guard fails the build.
- Executor tests that touch the OS belong in the integration tier; unit tests use the seams (`FakeRunner`, `SetNowForTest`, backend fakes) — see `docs/container-test-strategy.md` for the full strategy and the dormant-test trap it prevents.

## Running the container lanes locally

```bash
# Distro matrix lane (debian; swap the Dockerfile suffix for fedora/opensuse/archlinux)
cd .. && docker build -f agent/test/Dockerfile.integration -t pm-agent-test .
docker run --rm pm-agent-test \
  go test -tags=integration -count=1 -timeout=10m ./agent/internal/executor/ -run Integration

# Privileged edge lane
docker run --rm --privileged pm-agent-test \
  go test -tags=integration -count=1 -timeout=10m ./agent/internal/executor/ -run EdgeCase
```

The build context is the **parent** directory: CI checks the repo out into `agent/` and optionally overlays a same-named SDK branch into `sdk/` (the go.mod pin is used otherwise).

## Docs

`README.md` and `docs/` are docref-anchored: run `docker run --rm -v "$PWD:/repo" ghcr.io/manchtools/open-docref:v0.1.0 check` before pushing doc or code changes that touch anchored symbols; CI fails on drift. Update the prose *and* re-approve the claim — never delete an anchor to silence the check.
