// Package main is the entry point for the power-manage agent.
package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/manchtools/power-manage/agent/internal/luksd"

	"golang.org/x/term"
)

// runLuks handles the "luks" subcommand.
// Usage: power-manage-agent luks set-passphrase --token XXX
//
// This CLI is UNPRIVILEGED (WS6 #1/#19). It collects the passphrase and
// hands {token, passphrase} to the root agent's LUKS daemon socket, which
// performs all privileged cryptsetup work with its own credentials. There
// is no --data-dir flag and no sudoers rule: the old design ran this under
// NOPASSWD sudo with an attacker-controllable --data-dir, letting any
// local user point root's cryptsetup at a forged store + hostile gateway.
func runLuks(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: power-manage-agent luks set-passphrase --token <token>")
		os.Exit(1)
	}

	switch args[0] {
	case "set-passphrase":
		fs := flag.NewFlagSet("luks set-passphrase", flag.ExitOnError)
		token := fs.String("token", "", "One-time LUKS passphrase token")
		fs.Parse(args[1:])

		if *token == "" {
			fmt.Fprintln(os.Stderr, "error: --token is required")
			fmt.Fprintln(os.Stderr, "usage: power-manage-agent luks set-passphrase --token <token>")
			os.Exit(1)
		}

		runLuksSetPassphrase(*token)
	default:
		fmt.Fprintf(os.Stderr, "unknown luks subcommand: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: power-manage-agent luks set-passphrase --token <token>")
		os.Exit(1)
	}
}

// runLuksURI handles power-manage://luks/set-passphrase?token=XXX URIs.
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
