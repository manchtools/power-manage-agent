# Contributing to Power Manage Agent

## Prerequisites

- Go 1.25+
- A Linux system for testing (the agent manages Linux devices)

## Getting Started

This repo is part of a Go workspace. Clone all four repos (`sdk`, `server`, `agent`, `web`) into the same parent directory.

```bash
# Build
go build ./cmd/agent

# Run tests
go test ./...
```

See `CLAUDE.md` for the full build command reference.

## Workflow

1. Create a branch from `main`.
2. Make your changes with conventional commit messages:
   - `feat:` new feature
   - `fix:` bug fix
   - `chore:` maintenance
   - `docs:` documentation
   - `refactor:` code restructuring
   - `perf:` performance improvement
   - `test:` test additions/changes
3. Open a pull request. CodeRabbit reviews automatically.
4. Ensure CI passes before requesting review.

## Code Style

- Follow existing patterns in the codebase.
- Always handle errors -- never silently ignore them.

## Guardrails (architectural fitness functions)

`internal/archtest/` holds build-failing invariant tests that run in the
normal `go test ./...` path:

- **`TestNoDynamicSQL`** — the hand-written sqlite queries (`s.db`/`tx`) must
  use string-literal SQL with `?` placeholders; never `fmt.Sprintf`/
  concatenate SQL.
- **`TestSecretComparesAreConstantTime`** — compare secrets/tokens/MACs/
  signatures with `subtle.ConstantTimeCompare`/`hmac.Equal`, never
  `==`/`bytes.Equal`.
- **`TestNoUnabstractedTimeNow`** — no direct `time.Now()` calls in runtime
  code. Read the clock through an injected `now func() time.Time` seam
  (defaulting to `time.Now`) and call `t.now()`, so time-dependent logic (the
  offline scheduler's maintenance-window gate, expiry, rotation cutoffs) is
  testable with a fixed clock.

Each guard ships a documented, no-stale-guarded allowlist for genuine
exceptions. **Prefer fixing the code over adding an allowlist entry.** The
rationale lives in the server repo's `docs/adr/0002-architectural-fitness-functions.md`.

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
