// Package main is the entry point for the power-manage agent.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/manchtools/power-manage/agent/internal/luksd"

	"golang.org/x/term"
)

// luksTokenEnv delivers the one-time LUKS token without argv.
// /proc/<pid>/environ is readable only by the process's own uid, unlike
// /proc/<pid>/cmdline, which every local user can read.
const luksTokenEnv = "PM_LUKS_TOKEN"

const luksUsage = "usage: power-manage-agent luks set-passphrase [--token-file <path>|-]\n" +
	"       the token may also come from $" + luksTokenEnv + ", or be typed at the prompt"

// runLuks handles the "luks" subcommand.
//
// This CLI is unprivileged. It collects the passphrase and hands
// {token, passphrase} to the root agent's LUKS daemon socket, which performs
// all privileged cryptsetup work with its own credentials.
func runLuks(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, luksUsage)
		os.Exit(1)
	}

	switch args[0] {
	case "set-passphrase":
		fs := flag.NewFlagSet("luks set-passphrase", flag.ExitOnError)
		tokenFile := fs.String("token-file", "",
			"File holding the one-time LUKS token, mode 0600 (\"-\" reads it from stdin)")
		fs.Parse(args[1:])

		token, err := resolveLuksToken(*tokenFile, os.Getenv(luksTokenEnv), os.Stdin, promptToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			fmt.Fprintln(os.Stderr, luksUsage)
			os.Exit(1)
		}

		runLuksSetPassphrase(token)
	default:
		fmt.Fprintf(os.Stderr, "unknown luks subcommand: %s\n", args[0])
		fmt.Fprintln(os.Stderr, luksUsage)
		os.Exit(1)
	}
}

// resolveLuksToken resolves the one-time LUKS token without ever taking it from
// argv. Process arguments are world-readable through /proc/<pid>/cmdline, and
// the client collects the passphrase BEFORE it dials the daemon, so a token on
// argv sat there for the whole interactive typing window while being the sole
// authorization for a root daemon that writes LUKS keyslots (F2).
//
// Order: an explicit token file (or stdin via "-"), then the environment, then
// an interactive prompt. It fails closed when none of them produced a token.
func resolveLuksToken(tokenFile, envToken string, stdin io.Reader, prompt func() (string, error)) (string, error) {
	if tokenFile != "" {
		token, err := readLuksTokenFile(tokenFile, stdin)
		if err != nil {
			return "", err
		}
		if token == "" {
			return "", fmt.Errorf("token file %s is empty", tokenFile)
		}
		return token, nil
	}
	if token := strings.TrimSpace(envToken); token != "" {
		return token, nil
	}
	if prompt != nil {
		token, err := prompt()
		if err != nil {
			return "", err
		}
		if token = strings.TrimSpace(token); token != "" {
			return token, nil
		}
	}
	return "", errors.New("no LUKS token supplied")
}

// readLuksTokenFile reads a token from path, or from stdin when path is "-".
// A file any other local user can read is the same leak as argv by another
// route, so it is refused rather than warned about.
func readLuksTokenFile(path string, stdin io.Reader) (string, error) {
	if path == "-" {
		if stdin == nil {
			return "", errors.New("--token-file - was given but stdin is unavailable")
		}
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read token from stdin: %w", err)
		}
		return strings.TrimSpace(line), nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read token file %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("token file %s is mode %04o; it must not be readable beyond its owner (chmod 600 %s)", path, perm, path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read token file %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// promptToken reads the token from the terminal without echoing it. Typed
// rather than passed, it never reaches argv or a file at all.
func promptToken() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", nil // not interactive: let the caller report the missing token
	}
	fmt.Print("Enter the one-time LUKS token: ")
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read token: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// runLuksURI handles power-manage://luks/set-passphrase?token=XXX URIs.
//
// The URI carries the token on argv by construction — a desktop handler is
// invoked as `power-manage-agent %u` — which the CLI routes above deliberately
// avoid. That residual exposure is why the daemon authenticates the socket peer
// as well (agent/internal/luksd/peercred.go); the CLI form remains the
// advertised route.
func runLuksURI(rawURI string) {
	// Strict PREFIX rewrite (#174): strings.Replace on the first
	// occurrence anywhere would let a crafted URI like
	// power-manage://power-manage://evil/... shift the scheme swap into
	// the middle of the string; a URI that doesn't START with our scheme
	// is rejected outright.
	if !strings.HasPrefix(rawURI, "power-manage://") {
		fmt.Fprintf(os.Stderr, "error: not a power-manage:// URI\n")
		os.Exit(1)
	}
	normalizedURI := "https://" + strings.TrimPrefix(rawURI, "power-manage://")
	parsed, err := url.Parse(normalizedURI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid URI: %v\n", err)
		os.Exit(1)
	}

	token := parsed.Query().Get("token")
	if token == "" {
		fmt.Fprintln(os.Stderr, "error: token parameter is required in URI")
		os.Exit(1)
	}

	runLuksSetPassphrase(token)

	// Wait for Enter before closing (launched via desktop handler, terminal would close)
	fmt.Println("\nPress Enter to close...")
	fmt.Scanln()
	os.Exit(0)
}

// runLuksSetPassphrase collects the passphrase and submits it to the root
// LUKS daemon over the unix socket. All token validation, policy/reuse
// enforcement, and cryptsetup work happen daemon-side.
func runLuksSetPassphrase(token string) {
	client := luksd.NewClient(luksd.DefaultSocketPath)
	if err := client.SetPassphrase(token, promptPassphrase); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("LUKS passphrase set successfully.")
}

// promptPassphrase interactively reads and confirms a passphrase (up to 3
// attempts for a matching pair). It applies only a basic length floor as
// UX — the daemon is the authority on complexity and reuse. Returns an
// empty string (no error) when the user fails to provide a matching
// passphrase, so the client refuses to contact the daemon.
func promptPassphrase() (string, error) {
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		remaining := maxAttempts - attempt

		fmt.Print("Enter LUKS passphrase: ")
		pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("failed to read passphrase: %w", err)
		}

		fmt.Print("Confirm passphrase: ")
		pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("failed to read confirmation: %w", err)
		}

		if string(pw1) != string(pw2) {
			if remaining > 0 {
				fmt.Printf("Passphrases do not match. %d attempt(s) remaining.\n", remaining)
			}
			continue
		}

		candidate := string(pw1)
		// Basic length floor for UX so an obviously-too-short passphrase
		// does not consume the one-time token; the daemon enforces the
		// authoritative minimum and complexity.
		if len(candidate) < 16 {
			if remaining > 0 {
				fmt.Printf("Passphrase must be at least 16 characters. %d attempt(s) remaining.\n", remaining)
			}
			continue
		}
		return candidate, nil
	}

	fmt.Fprintln(os.Stderr, "Too many failed attempts.")
	return "", nil
}
