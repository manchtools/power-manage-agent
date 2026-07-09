module github.com/manchtools/power-manage/agent

go 1.25.12

require (
	connectrpc.com/connect v1.18.1
	github.com/manchtools/power-manage-sdk v0.5.4-0.20260709091948-db56f7940806
	github.com/oklog/ulid/v2 v2.1.0
	github.com/pressly/goose/v3 v3.26.0
	github.com/robfig/cron/v3 v3.0.1
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.52.0
	golang.org/x/term v0.43.0
	google.golang.org/protobuf v1.36.11
	modernc.org/sqlite v1.44.3
)

// The SDK import path differs from the actual GitHub repo URL
// (monorepo-style import path, polyrepo actual layout). Map it here
// so every `go build` uses a specific, pinned SDK commit rather than
// whatever happens to be in a local ../sdk checkout. Developers who
// want to iterate against a local SDK override this with a per-dev
// go.work at their workspace root — see agent/README.md for setup.
//
// Pin lifecycle (audit F034): this hash is bumped manually after the
// SDK PR that introduces a new server-visible behaviour merges. The
// agent maintainer runs `go get
// github.com/manchtools/power-manage-sdk@<commit>` and commits the
// resulting go.mod/go.sum together with the agent change that consumes
// it. There is no automatic floating tag — that's intentional, because
// SDK proto/Go API drifts between commits should be reviewable in the
// same PR as the agent change that consumes them.

require (
	dario.cat/mergo v1.0.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.6 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/go-cmd/cmd v1.4.3 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.0 // indirect
	github.com/go-git/go-git/v5 v5.19.1 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.1 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/sethvargo/go-retry v0.3.0 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
