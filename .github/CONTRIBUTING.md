# Contributing to Power Manage Agent

## Prerequisites

- Go 1.25+
- A Linux system for testing (the agent manages Linux devices; integration
  tests exercise real package managers and system services)

## Getting started

The agent builds standalone against its pinned SDK dependency:

```bash
go build ./cmd/power-manage-agent
go test ./...
```

For coordinated changes against a local SDK checkout, clone
[power-manage-sdk](https://github.com/manchtools/power-manage-sdk) beside this
repository and point a `go.work` at it:

```bash
go work init . && go work edit -replace github.com/manchtools/power-manage-sdk=../sdk
```

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

## Code style

- Follow existing patterns in the codebase.
- Always handle errors — never silently ignore them.
- Bug fixes come with a regression test that fails on the buggy version.

## Guardrails (architectural fitness functions)

`internal/archtest/` holds build-failing invariant tests that run in the
normal `go test ./...` path. Among what they enforce: string-literal SQL with
`?` placeholders only, constant-time comparison of secrets and signatures, no
unabstracted `time.Now()` in runtime code, no `context.Background()` in
request paths, no `math/rand` for anything cryptographic, no proto secret
fields reaching log or error sinks, no direct OS I/O in sensitive paths, and
no return of the abolished pre-rewrite agent runtime. Read the test files in
that package for the full, current list — the tests are the authority, not
this summary.

Each guard ships a documented allowlist for genuine exceptions. **Prefer
fixing the code over adding an allowlist entry.**

## License

By contributing, you agree that your contributions will be licensed under the
repository's [GPL-3.0](../LICENSE) license.
