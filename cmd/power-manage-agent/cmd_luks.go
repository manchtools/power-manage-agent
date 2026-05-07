// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	"github.com/manchtools/power-manage/agent/internal/store"
	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sdk "github.com/manchtools/power-manage/sdk/go"
	sysenc "github.com/manchtools/power-manage/sdk/go/sys/encryption"

	"golang.org/x/term"
)

// runLuks handles the "luks" subcommand.
// Usage: power-manage-agent luks set-passphrase --token XXX
func runLuks(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: power-manage-agent luks set-passphrase --token <token>")
		os.Exit(1)
	}

	switch args[0] {
	case "set-passphrase":
		fs := flag.NewFlagSet("luks set-passphrase", flag.ExitOnError)
		token := fs.String("token", "", "One-time LUKS passphrase token")
		dataDir := fs.String("data-dir", credentials.DefaultDataDir, "Data directory for credentials")
		fs.Parse(args[1:])

		if *token == "" {
			fmt.Fprintln(os.Stderr, "error: --token is required")
			fmt.Fprintln(os.Stderr, "usage: power-manage-agent luks set-passphrase --token <token>")
			os.Exit(1)
		}

		runLuksSetPassphrase(*token, *dataDir)
	default:
		fmt.Fprintf(os.Stderr, "unknown luks subcommand: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: power-manage-agent luks set-passphrase --token <token>")
		os.Exit(1)
	}
}

// runLuksURI handles power-manage://luks/set-passphrase?token=XXX URIs.
func runLuksURI(rawURI string) {
	normalizedURI := strings.Replace(rawURI, "power-manage://", "https://", 1)
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

	runLuksSetPassphrase(token, credentials.DefaultDataDir)

	// Wait for Enter before closing (launched via desktop handler, terminal would close)
	fmt.Println("\nPress Enter to close...")
	fmt.Scanln()
	os.Exit(0)
}

// runLuksSetPassphrase interactively sets a user passphrase on the LUKS device-bound key slot.
func runLuksSetPassphrase(token, dataDir string) {
	ctx := context.Background()

	// Load agent credentials
	credStore := credentials.NewStore(dataDir)
	if !credStore.Exists() {
		fmt.Fprintln(os.Stderr, "error: agent is not registered. Run the agent first.")
		os.Exit(1)
	}
	creds, err := credStore.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to load credentials: %v\n", err)
		os.Exit(1)
	}

	// Connect to gateway via mTLS. rc10 refuses http:// here too —
	// the luks-setup command path is production-only (ships via the
	// packaged binary on managed devices), so an http:// gateway
	// would mean the stored credentials are stale or tampered.
	if strings.HasPrefix(creds.GatewayAddr, "http://") {
		fmt.Fprintf(os.Stderr, "error: refusing h2c gateway URL (%s) — agent requires https:// for gateway connections\n", creds.GatewayAddr)
		os.Exit(1)
	}
	mtlsOpt, err := sdk.WithMTLSFromPEM(creds.Certificate, creds.PrivateKey, creds.CACert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to configure mTLS: %v\n", err)
		os.Exit(1)
	}
	client := sdk.NewClient(creds.GatewayAddr,
		mtlsOpt,
		sdk.WithAuth(creds.DeviceID, ""),
	)

	// Validate token — server returns action details and complexity requirements
	result, err := client.ValidateLuksToken(ctx, token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: token is invalid or has expired. Generate a new one from the web UI.")
		os.Exit(1)
	}

	// Map proto complexity to SDK complexity
	var complexity sysenc.Complexity
	switch result.Complexity {
	case pm.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_ALPHANUMERIC:
		complexity = sysenc.ComplexityAlphanumeric
	case pm.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX:
		complexity = sysenc.ComplexityComplex
	default:
		complexity = sysenc.ComplexityNone
	}

	minLength := int(result.MinLength)
	if minLength < 16 {
		minLength = 16
	}

	// Load passphrase history for reuse check
	agentStore, err := store.New(dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to open agent store: %v\n", err)
		os.Exit(1)
	}
	defer agentStore.Close()

	recentHashes, err := agentStore.GetLuksPassphraseHashes(result.ActionID)
	if err != nil {
		slog.Warn("failed to get LUKS passphrase hashes", "action_id", result.ActionID, "error", err)
	}

	// Interactive passphrase prompt (up to 3 attempts)
	const maxAttempts = 3
	var passphrase string

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		remaining := maxAttempts - attempt

		fmt.Print("Enter LUKS passphrase: ")
		pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to read passphrase: %v\n", err)
			os.Exit(1)
		}

		fmt.Print("Confirm passphrase: ")
		pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to read confirmation: %v\n", err)
			os.Exit(1)
		}

		if string(pw1) != string(pw2) {
			if remaining > 0 {
				fmt.Printf("Passphrases do not match. %d attempt(s) remaining.\n", remaining)
			}
			continue
		}

		candidate := string(pw1)

		// Validate complexity
		if validationErr := sysenc.ValidatePassphrase(candidate, minLength, complexity); validationErr != "" {
			if remaining > 0 {
				fmt.Printf("%s %d attempt(s) remaining.\n", validationErr, remaining)
			}
			continue
		}

		// Check reuse
		if sysenc.IsRecentlyUsed(candidate, recentHashes) {
			if remaining > 0 {
				fmt.Printf("This passphrase was used recently. Choose a different one. %d attempt(s) remaining.\n", remaining)
			}
			continue
		}

		passphrase = candidate
		break
	}

	if passphrase == "" {
		fmt.Fprintln(os.Stderr, "Too many failed attempts.")
		os.Exit(1)
	}

	// Connect stream for GetLuksKey (stream-based request-response)
	if err := client.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to connect to gateway: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	hostname, err := os.Hostname()
	if err != nil {
		slog.Warn("failed to get hostname", "error", err)
	}
	if err := client.SendHello(ctx, hostname, version); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to send hello: %v\n", err)
		os.Exit(1)
	}

	stopReceiver := client.StartReceiver(ctx)
	defer stopReceiver()

	// Get managed passphrase from server (in memory only)
	managedKey, err := client.GetLuksKey(ctx, result.ActionID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to get managed key: %v\n", err)
		os.Exit(1)
	}

	devicePath := result.DevicePath

	// Check current device key type and revoke if needed
	localState, _ := agentStore.GetLuksState(result.ActionID)
	if localState != nil && localState.DeviceKeyType != "none" {
		fmt.Println("Revoking current device-bound key...")
		switch localState.DeviceKeyType {
		case "tpm":
			if err := sysenc.WipeTPM(ctx, devicePath, managedKey); err != nil {
				fmt.Fprintf(os.Stderr, "error: failed to wipe TPM key: %v\n", err)
				os.Exit(1)
			}
		case "user_passphrase":
			if err := sysenc.KillSlot(ctx, devicePath, 7, managedKey); err != nil {
				fmt.Fprintf(os.Stderr, "error: failed to remove existing passphrase: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Add user passphrase to slot 7
	fmt.Println("Setting LUKS passphrase...")
	if err := sysenc.AddKeyToSlot(ctx, devicePath, 7, managedKey, passphrase); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to set passphrase: %v\nManaged key may have been rotated.\n", err)
		os.Exit(1)
	}

	// Update local state
	agentStore.SetLuksDeviceKeyType(result.ActionID, "user_passphrase")

	// Store passphrase hash for reuse prevention (keeps last 3)
	agentStore.AddLuksPassphraseHash(result.ActionID, sysenc.HashPassphrase(passphrase))

	fmt.Println("LUKS passphrase set successfully.")
}
