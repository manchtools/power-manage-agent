// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	sdk "github.com/manchtools/power-manage/sdk/go"
	"github.com/manchtools/power-manage/sdk/go/logging"
)

// runSelfTest runs a minimal connectivity probe to validate that this binary
// can function as the agent. Called by the old binary during self-update to
// verify the new binary before swapping it in. Exits 0 on success, 1 on failure.
//
// The probe:
//  1. Loads credentials from the data directory
//  2. Establishes an mTLS connection to the gateway
//  3. Sends Hello, waits for Welcome (proves bidirectional stream)
//  4. Calls SyncActions (proves unary RPC works)
//
// Does NOT start the scheduler, open the enrollment socket, execute actions,
// or modify any local state. Read-only connectivity check.
//
// Session-conflict caveat: the self-test connects with the same device identity
// as the live agent, and the gateway's connection manager closes any existing
// stream on re-register (see server internal/connection/manager.go Register).
// Consequence: the live agent briefly disconnects during the self-test and
// reconnects when the subprocess exits — typically 3-5 seconds of offline
// time. This is an accepted tradeoff; removing it would require either an
// ephemeral self-test identity (signed by the CA on demand) or a dedicated
// server endpoint that bypasses the registry.
func runSelfTest(args []string) int {
	fs := flag.NewFlagSet("self-test", flag.ExitOnError)
	dataDir := fs.String("data-dir", credentials.DefaultDataDir, "Agent data directory")
	timeout := fs.Duration("timeout", 60*time.Second, "Self-test timeout")
	fs.Parse(args)

	logger := logging.SetupLogger("info", "text", os.Stderr)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Step 1: Load credentials
	credStore := credentials.NewStore(*dataDir)
	if !credStore.Exists() {
		logger.Error("self-test: no credentials found", "data_dir", *dataDir)
		return 1
	}
	creds, err := credStore.Load()
	if err != nil {
		logger.Error("self-test: failed to load credentials", "error", err)
		return 1
	}
	logger.Info("self-test: credentials loaded", "device_id", creds.DeviceID)

	// Step 2: Create mTLS client. rc10 refuses anything but https://host
	// here: the self-test is invoked by the packaged install flow on
	// managed devices and must exercise the same security posture as
	// normal agent operation. Shared predicate with runtime.go so the
	// guard cannot drift between dial sites.
	gatewayAddr := strings.TrimSpace(creds.GatewayAddr)
	if err := requireHTTPSGateway(creds.GatewayAddr); err != nil {
		logger.Error("self-test: refusing gateway URL", "gateway", creds.GatewayAddr, "error", err)
		return 1
	}
	mtlsOpt, err := sdk.WithMTLSFromPEM(creds.Certificate, creds.PrivateKey, creds.CACert)
	if err != nil {
		logger.Error("self-test: failed to configure mTLS", "error", err)
		return 1
	}
	client := sdk.NewClient(gatewayAddr,
		mtlsOpt,
		sdk.WithAuth(creds.DeviceID, ""),
	)

	// Step 3: Connect and send Hello, wait for Welcome
	if err := client.Connect(ctx); err != nil {
		logger.Error("self-test: failed to connect to gateway", "error", err)
		return 1
	}
	defer client.Close()

	hostname, _ := os.Hostname()
	if err := client.SendHello(ctx, hostname, version); err != nil {
		logger.Error("self-test: failed to send hello", "error", err)
		return 1
	}

	// Wait for Welcome message (proves bidirectional stream works)
	msg, err := client.Receive(ctx)
	if err != nil {
		logger.Error("self-test: failed to receive welcome", "error", err)
		return 1
	}
	if msg.GetWelcome() == nil {
		logger.Error("self-test: expected welcome message, got something else")
		return 1
	}
	logger.Info("self-test: stream connected, welcome received",
		"server_version", msg.GetWelcome().ServerVersion)

	// Step 4: Call SyncActions (proves unary RPC path works)
	_, err = client.SyncActions(ctx)
	if err != nil {
		logger.Error("self-test: sync actions failed", "error", err)
		return 1
	}
	logger.Info("self-test: sync actions succeeded")

	logger.Info("self-test: all checks passed")
	return 0
}
