module github.com/manchtools/power-manage/agent

go 1.25

require (
	github.com/go-cmd/cmd v1.4.3
	github.com/go-playground/validator/v10 v10.30.1
	github.com/manchtools/power-manage/sdk v0.0.0
	github.com/oklog/ulid/v2 v2.1.0
	golang.org/x/crypto v0.47.0
	google.golang.org/protobuf v1.36.4
	modernc.org/sqlite v1.44.3
)

require (
	connectrpc.com/connect v1.18.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/manchtools/power-manage/sdk => ../sdk
