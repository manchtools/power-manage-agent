// Package setup provides agent installation helpers including sudoers configuration.
package setup

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// validUsername matches safe Unix usernames (lowercase, digits, underscore, dash).
var validUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

//go:embed sudoers.tmpl
var sudoersTmpl string

//go:embed doas.tmpl
var doasTmpl string

// SudoersData holds template data for rendering the sudoers file.
type SudoersData struct {
	User string
}

// DoasData holds template data for rendering the doas.conf fragment.
type DoasData struct {
	User string
}

// InstallSudoers renders the embedded sudoers template and installs it to
// /etc/sudoers.d/<user>. The file is validated with visudo before installation.
// Must be run as root.
func InstallSudoers(user string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root")
	}

	if user == "" {
		return fmt.Errorf("user name is required")
	}
	if !validUsername.MatchString(user) {
		return fmt.Errorf("invalid user name: must match [a-z_][a-z0-9_-]*")
	}

	tmpl, err := template.New("sudoers").Parse(sudoersTmpl)
	if err != nil {
		return fmt.Errorf("parse sudoers template: %w", err)
	}

	dest := fmt.Sprintf("/etc/sudoers.d/%s", user)
	tmpFile := dest + ".tmp"

	// Render template to temp file
	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0440)
	if err != nil {
		return fmt.Errorf("create temp sudoers file: %w", err)
	}

	if err := tmpl.Execute(f, SudoersData{User: user}); err != nil {
		_ = f.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("render sudoers template: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("close temp sudoers file: %w", err)
	}

	// Short deadline on these: visudo/chown are millisecond-scale but
	// should never hang if something is wrong with the host.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Validate syntax with visudo
	if result, err := sysexec.Run(ctx, "visudo", "-c", "-f", tmpFile); err != nil {
		os.Remove(tmpFile)
		if result != nil && result.Stderr != "" {
			return fmt.Errorf("sudoers validation failed: %w: %s", err, result.Stderr)
		}
		return fmt.Errorf("sudoers validation failed: %w", err)
	}

	// Atomically move into place
	if err := os.Rename(tmpFile, dest); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("install sudoers file: %w", err)
	}

	// Ensure correct ownership
	if result, err := sysexec.Run(ctx, "chown", "root:root", dest); err != nil {
		if result != nil && result.Stderr != "" {
			return fmt.Errorf("set sudoers ownership: %w: %s", err, result.Stderr)
		}
		return fmt.Errorf("set sudoers ownership: %w", err)
	}

	return nil
}

// InstallDoas renders the embedded doas template and installs it to
// /etc/doas.d/<user>.conf. Ordering matters for the failure mode: the
// /etc/doas.conf include check runs BEFORE the temp-file rename, so a
// misconfigured main conf causes setup to abort without leaving an
// inert root-permit fragment on disk. The fragment is also validated
// with `doas -C` before the include check so a syntax error is
// surfaced first (more useful signal to the operator).
//
// Must be run as root.
func InstallDoas(user string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root")
	}

	if user == "" {
		return fmt.Errorf("user name is required")
	}
	if !validUsername.MatchString(user) {
		return fmt.Errorf("invalid user name: must match [a-z_][a-z0-9_-]*")
	}

	tmpl, err := template.New("doas").Parse(doasTmpl)
	if err != nil {
		return fmt.Errorf("parse doas template: %w", err)
	}

	// /etc/doas.d is not universally present (OpenBSD ships only
	// /etc/doas.conf). Create it on Linux systems running opendoas;
	// mode 0755 matches the permissions doas.conf itself expects.
	const doasDir = "/etc/doas.d"
	if err := os.MkdirAll(doasDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", doasDir, err)
	}

	dest := fmt.Sprintf("%s/%s.conf", doasDir, user)
	tmpFile := dest + ".tmp"

	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("create temp doas file: %w", err)
	}

	if err := tmpl.Execute(f, DoasData{User: user}); err != nil {
		_ = f.Close()
		os.Remove(tmpFile)
		return fmt.Errorf("render doas template: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("close temp doas file: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Validate syntax with `doas -C <file>`. Non-zero exit means the
	// rule doesn't parse — refuse to install so the agent can't leave
	// the host with a broken policy file.
	if result, err := sysexec.Run(ctx, "doas", "-C", tmpFile); err != nil {
		os.Remove(tmpFile)
		if result != nil && result.Stderr != "" {
			return fmt.Errorf("doas validation failed: %w: %s", err, result.Stderr)
		}
		return fmt.Errorf("doas validation failed: %w", err)
	}

	// Include-directive check runs BEFORE the rename. doas has no
	// implicit conf.d scan, so a drop-in that /etc/doas.conf doesn't
	// explicitly load is inert but still grants no-password root on
	// paper — fail hard rather than installing a silent
	// misconfiguration.
	if err := verifyDoasIncludeIn("/etc/doas.conf", dest); err != nil {
		os.Remove(tmpFile)
		return err
	}

	if err := os.Rename(tmpFile, dest); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("install doas file: %w", err)
	}

	if result, err := sysexec.Run(ctx, "chown", "root:root", dest); err != nil {
		if result != nil && result.Stderr != "" {
			return fmt.Errorf("set doas ownership: %w: %s", err, result.Stderr)
		}
		return fmt.Errorf("set doas ownership: %w", err)
	}

	return nil
}

// verifyDoasIncludeIn checks that mainConf has an `include` directive
// that would load fragmentPath. Accepts either an exact-path include
// or a glob (filepath.Match semantics) that matches the fragment.
// Unrelated includes of sibling drop-ins (e.g. `include
// "/etc/doas.d/other.conf"` when the fragment is power-manage.conf)
// do NOT satisfy the check — they'd pass a naive substring match but
// still leave the agent's rule unloaded.
//
// Takes the main-conf path as a parameter so tests can point at a
// fixture without touching the host's /etc/doas.conf; production
// callers pass "/etc/doas.conf".
func verifyDoasIncludeIn(mainConf, fragmentPath string) error {
	data, err := os.ReadFile(mainConf)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist; create it with an `include \"%s\"` line or the agent's rule will be ignored", mainConf, fragmentPath)
		}
		return fmt.Errorf("read %s: %w", mainConf, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		pattern, ok := parseDoasInclude(line)
		if !ok {
			continue
		}
		// Exact path match wins — the common operator setup is
		// `include "/etc/doas.d/power-manage.conf"`.
		if pattern == fragmentPath {
			return nil
		}
		// Otherwise try the pattern as a glob. Forks of doas that
		// honor glob (some opendoas builds) will load the fragment if
		// its name matches; we accept the same shapes so setup
		// doesn't refuse a valid config. filepath.Match returning an
		// error means the pattern is malformed — ignore it and
		// continue, treating it as "doesn't match".
		if match, err := filepath.Match(pattern, fragmentPath); err == nil && match {
			return nil
		}
	}
	return fmt.Errorf("%s has no `include` directive that loads %s; add `include \"%s\"` so doas actually loads the rule", mainConf, fragmentPath, fragmentPath)
}

// parseDoasInclude extracts the path argument from a doas `include`
// directive, returning (path, true) on success. Supports both quoted
// ("include \"/etc/doas.d/power-manage.conf\"") and unquoted
// ("include /etc/doas.d/power-manage.conf") forms, with arbitrary
// leading whitespace and optional inline comments after the path.
// Lines that aren't include directives return ("", false).
func parseDoasInclude(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "include") {
		return "", false
	}
	// Need a word-boundary after "include" — "included" or
	// "includeall" must not match.
	rest := trimmed[len("include"):]
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", false
	}
	// Drop an inline `#` comment past the path, if any.
	if i := strings.Index(rest, "#"); i >= 0 {
		rest = strings.TrimSpace(rest[:i])
	}
	// Strip surrounding quotes. doas.conf(5) accepts both forms.
	if len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"' {
		rest = rest[1 : len(rest)-1]
	}
	if rest == "" {
		return "", false
	}
	return rest, true
}
