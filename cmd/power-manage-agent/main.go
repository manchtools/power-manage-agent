// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	osexec "os/exec"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	"github.com/manchtools/power-manage/agent/internal/deviceauth"
	"github.com/manchtools/power-manage/agent/internal/executor"
	"github.com/manchtools/power-manage/agent/internal/handler"
	"github.com/manchtools/power-manage/agent/internal/scheduler"
	"github.com/manchtools/power-manage/agent/internal/setup"
	"github.com/manchtools/power-manage/agent/internal/store"
	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	sdk "github.com/manchtools/power-manage/sdk/go"
	pmcrypto "github.com/manchtools/power-manage/sdk/go/crypto"
	"github.com/manchtools/power-manage/sdk/go/logging"
	sysenc "github.com/manchtools/power-manage/sdk/go/sys/encryption"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/osquery"
	sysservice "github.com/manchtools/power-manage/sdk/go/sys/service"
	"github.com/manchtools/power-manage/sdk/go/verify"

	"golang.org/x/term"
)

// version is set at build time via -ldflags.
var version = "dev"

const (
	defaultHeartbeatInterval = 30 * time.Second
	defaultSyncInterval      = 30 * time.Minute

	// Exponential backoff constants for reconnection
	minInitialBackoff = 5 * time.Second
	maxInitialBackoff = 10 * time.Second
	maxBackoff        = 5 * time.Minute
	backoffFactor     = 2.0
)

// randomBackoff returns a random duration between minInitialBackoff and maxInitialBackoff.
func randomBackoff() time.Duration {
	jitter := rand.Int64N(int64(maxInitialBackoff - minInitialBackoff))
	return minInitialBackoff + time.Duration(jitter)
}

// applyBackendOverrides maps the backend strings resolved by
// parseFlags() onto the SDK's pluggable backend selectors. Called once
// at startup before any privileged helper runs. Unknown or empty
// values fall through to the default (sudo / systemd / luks) and the
// function pins the SDK explicitly rather than relying on zero-value
// state, so an unknown value is still deterministic.
//
// Returns an error if the selected backend's required binary isn't on
// PATH (e.g. POWER_MANAGE_PRIVILEGE_BACKEND=doas on a host with no
// doas installed). Fail-fast at startup is cheaper than debugging a
// "permission denied" on the first privileged call hours later.
func applyBackendOverrides(cfg *Config, logger *slog.Logger) error {
	// Privilege-escalation tool. sudo remains the default because
	// every mainstream Linux distro ships it; doas is for OpenBSD-
	// style setups and some BSD-influenced Linux deployments.
	var privilegeTool string
	switch cfg.PrivilegeBackend {
	case "doas":
		sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendDoas)
		privilegeTool = "doas"
	case "sudo", "":
		sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendSudo)
		privilegeTool = "sudo"
	default:
		logger.Warn("unknown POWER_MANAGE_PRIVILEGE_BACKEND, staying on sudo",
			"value", cfg.PrivilegeBackend)
		sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendSudo)
		privilegeTool = "sudo"
	}
	if _, err := osexec.LookPath(privilegeTool); err != nil {
		return fmt.Errorf("privilege backend %q selected but %q is not on PATH: %w",
			privilegeTool, privilegeTool, err)
	}
	logger.Info("privilege backend set", "backend", privilegeTool)

	// Service manager. Only systemd has a concrete implementation
	// today; the other backends are scaffolded in the SDK so the
	// proto enum + agent wiring stay stable, but WriteUnit / Enable /
	// Start return sysservice.unsupported(...) until implementations
	// land. Warn loudly so operators who select a scaffold backend
	// don't think the agent silently succeeded — the first action
	// will fail, but the warning explains why before that happens.
	var serviceTool string
	scaffoldOnly := false
	switch cfg.ServiceBackend {
	case "openrc":
		sysservice.SetServiceBackend(sysservice.ServiceBackendOpenRC)
		serviceTool = "rc-service"
		scaffoldOnly = true
	case "runit":
		sysservice.SetServiceBackend(sysservice.ServiceBackendRunit)
		serviceTool = "sv"
		scaffoldOnly = true
	case "s6":
		sysservice.SetServiceBackend(sysservice.ServiceBackendS6)
		serviceTool = "s6-svc"
		scaffoldOnly = true
	case "systemd", "":
		sysservice.SetServiceBackend(sysservice.ServiceBackendSystemd)
		serviceTool = "systemctl"
	default:
		logger.Warn("unknown POWER_MANAGE_SERVICE_BACKEND, staying on systemd",
			"value", cfg.ServiceBackend)
		sysservice.SetServiceBackend(sysservice.ServiceBackendSystemd)
		serviceTool = "systemctl"
	}
	if scaffoldOnly {
		logger.Warn("service backend has no SDK implementation yet; SERVICE actions will fail until support lands",
			"backend", cfg.ServiceBackend)
	}
	if _, err := osexec.LookPath(serviceTool); err != nil {
		return fmt.Errorf("service backend %q selected but %q is not on PATH: %w",
			normalizedServiceBackend(cfg.ServiceBackend), serviceTool, err)
	}
	logger.Info("service backend set", "backend", normalizedServiceBackend(cfg.ServiceBackend))

	// Disk-encryption tooling. Only LUKS is implemented today.
	// GELI/CGD live on BSD where we don't probe for a specific CLI
	// binary — the SDK's encryption package handles detection there.
	var encName string
	switch cfg.EncryptionBackend {
	case "geli":
		sysenc.SetBackend(sysenc.BackendGELI)
		encName = "geli"
	case "cgd":
		sysenc.SetBackend(sysenc.BackendCGD)
		encName = "cgd"
	case "luks", "":
		sysenc.SetBackend(sysenc.BackendLUKS)
		encName = "luks"
	default:
		logger.Warn("unknown POWER_MANAGE_ENCRYPTION_BACKEND, staying on luks",
			"value", cfg.EncryptionBackend)
		sysenc.SetBackend(sysenc.BackendLUKS)
		encName = "luks"
	}
	if encName == "luks" {
		if _, err := osexec.LookPath("cryptsetup"); err != nil {
			// Not fatal — devices without encryption actions assigned
			// don't need cryptsetup. Warn so operators troubleshooting
			// a failed encryption action have the context.
			logger.Warn("luks backend selected but cryptsetup not on PATH; encryption actions will fail",
				"error", err)
		}
	}
	logger.Info("encryption backend set", "backend", encName)

	return nil
}

// normalizedServiceBackend returns the canonical name for logging so
// the empty-string default case doesn't log "service backend set
// backend=" with a blank value.
func normalizedServiceBackend(s string) string {
	if s == "" {
		return "systemd"
	}
	return s
}

// Config holds the agent configuration.
type Config struct {
	// Registration
	Token      string
	ServerURL  string
	SkipVerify bool

	// Storage
	DataDir string

	// Logging
	LogLevel  string
	LogFormat string

	// Backend selections resolved from POWER_MANAGE_*_BACKEND env vars
	// at parseFlags() time. Stored as lowercase strings because the SDK
	// enum conversion lives inside applyBackendOverrides — keeping the
	// Config free of SDK types makes the struct trivially serializable
	// and keeps parseFlags a pure string parser. Empty means "default".
	PrivilegeBackend  string
	ServiceBackend    string
	EncryptionBackend string

	// Pending security alert to send after connection (internal use)
	pendingSecurityAlert *pendingSecurityAlert
}

// pendingSecurityAlert holds data for a security alert to be sent after connection.
type pendingSecurityAlert struct {
	alertType        string
	message          string
	requestedServer  string
	registeredServer string
}

// clientLuksKeyStore adapts sdk.Client to the executor.LuksKeyStore interface.
type clientLuksKeyStore struct {
	client *sdk.Client
}

func (s *clientLuksKeyStore) GetKey(ctx context.Context, actionID string) (string, error) {
	return s.client.GetLuksKey(ctx, actionID)
}

func (s *clientLuksKeyStore) StoreKey(ctx context.Context, actionID, devicePath, passphrase, reason string) error {
	return s.client.StoreLuksKey(ctx, actionID, devicePath, passphrase, reason)
}

func main() {
	// Check for subcommands before parsing flags
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("power-manage-agent %s\n", version)
			return
		case "setup", "--setup", "-setup":
			runSetup(os.Args[2:])
			return
		case "query", "--query", "-query":
			runQuery(os.Args[2:])
			return
		case "luks":
			runLuks(os.Args[2:])
			return
		case "enroll":
			runEnroll(os.Args[2:])
			return
		case "self-test":
			os.Exit(runSelfTest(os.Args[2:]))
		case "tty":
			os.Exit(runTTY(os.Args[2:]))
		}
	}

	cfg := parseFlags()

	// Setup logger
	logger := logging.SetupLogger(cfg.LogLevel, cfg.LogFormat, os.Stdout)
	slog.SetDefault(logger)
	logger.Info("logger initialized", "level", cfg.LogLevel, "format", cfg.LogFormat)

	// Select SDK pluggable backends BEFORE any privileged call fires.
	// Defaults stay at sudo / systemd / luks so every existing
	// Linux-systemd-sudo deployment continues working with no
	// configuration; operators on OpenBSD-style doas or OpenRC-flavoured
	// systems flip the backend once via env var.
	if err := applyBackendOverrides(cfg, logger); err != nil {
		logger.Error("backend validation failed", "error", err)
		os.Exit(1)
	}

	// Clean up stale update state from a previous cycle (if any).
	executor.CheckStartupUpdateState(cfg.DataDir, logger)

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		logger.Error("failed to get hostname", "error", err)
		os.Exit(1)
	}

	// Create context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	// Initialize credential store
	credStore := credentials.NewStore(cfg.DataDir)

	// Load or obtain credentials
	var creds *credentials.Credentials
	if credStore.Exists() {
		logger.Info("loading stored credentials", "data_dir", credStore.DataDir())
		creds, err = credStore.Load()
		if err != nil {
			logger.Error("failed to load credentials", "error", err)
			logger.Info("hint: delete stored credentials to re-register",
				"path", credStore.DataDir())
			os.Exit(1)
		}
		logger.Info("credentials loaded",
			"device_id", creds.DeviceID,
			"gateway", creds.GatewayAddr,
		)

		// Ignore registration token if already registered
		if cfg.Token != "" {
			logger.Debug("ignoring registration token - agent is already registered")
		}
	} else if cfg.Token != "" {
		// Direct registration (backwards compatible, works with sudo)
		if cfg.ServerURL == "" {
			logger.Error("server URL required for registration")
			os.Exit(1)
		}

		creds, err = register(ctx, cfg, hostname, logger)
		if err != nil {
			logger.Error("registration failed", "error", err)
			os.Exit(1)
		}

		// Save credentials
		if err := credStore.Save(creds); err != nil {
			logger.Error("failed to save credentials", "error", err)
			os.Exit(1)
		}
		logger.Info("credentials saved", "data_dir", credStore.DataDir())
	} else {
		// No credentials and no token — start enrollment socket and wait
		logger.Info("agent not enrolled, waiting for enrollment via socket",
			"socket", deviceauth.EnrollSocketPath)

		enrollCh := make(chan *credentials.Credentials, 1)
		enrollHandler := deviceauth.NewEnrollHandler(hostname, version, credStore, logger, func(c *credentials.Credentials) {
			enrollCh <- c
		})
		enrollServer := deviceauth.NewEnrollServer(enrollHandler, deviceauth.EnrollSocketPath, logger)

		go func() {
			if err := enrollServer.Start(ctx); err != nil {
				logger.Error("enrollment server failed", "error", err)
			}
		}()

		select {
		case creds = <-enrollCh:
			logger.Info("enrollment complete", "device_id", creds.DeviceID)
			enrollServer.Shutdown()
		case <-ctx.Done():
			logger.Info("agent stopped while waiting for enrollment")
			return
		}
	}

	// Initialize the action store for offline persistence
	actionStore, err := store.New(cfg.DataDir)
	if err != nil {
		logger.Error("failed to initialize action store", "error", err)
		os.Exit(1)
	}
	defer actionStore.Close()

	// Initialize action signature verifier from the CA certificate (required)
	var actionVerifier *verify.ActionVerifier
	if len(creds.CACert) > 0 {
		v, err := verify.NewActionVerifier(creds.CACert)
		if err != nil {
			logger.Error("failed to initialize action verifier", "error", err)
			os.Exit(1)
		}
		actionVerifier = v
		logger.Info("action signature verification enabled")
	} else {
		logger.Error("CA certificate missing from credentials, cannot verify action signatures")
		os.Exit(1)
	}

	// Initialize the scheduler for autonomous action execution
	exec := executor.NewExecutor(actionVerifier)
	exec.SetStore(actionStore)
	sched := scheduler.New(actionStore, exec, logger)
	exec.SetActionStore(sched)

	// Start the scheduler in a goroutine
	go sched.Start(ctx)

	// Create sync trigger channel for instant SYNC actions
	syncTrigger := make(chan struct{}, 1)

	// Create handler with scheduler integration
	h := handler.NewHandler(logger, exec, sched, actionStore, syncTrigger)

	// Enable action-based agent self-update.
	exec.SetUpdateConfig(&executor.AgentUpdateConfig{
		Version:    version,
		DataDir:    cfg.DataDir,
		BinaryPath: "/usr/local/bin/power-manage-agent",
		Shutdown:   cancel,
	})

	// Start certificate rotation goroutine
	if creds.ControlAddr != "" {
		go startCertRotation(ctx, credStore, hostname, logger)
	}

	// Run the agent
	logger.Info("starting agent",
		"gateway", creds.GatewayAddr,
		"device_id", creds.DeviceID,
		"hostname", hostname,
		"version", version,
	)

	runAgent(ctx, creds, hostname, h, sched, syncTrigger, cfg.pendingSecurityAlert, logger)
}

// register performs initial registration with the control server.
// The agent generates its own key pair locally and sends a CSR to the control server.
// The private key never leaves the agent. The control server returns the gateway URL
// for subsequent mTLS streaming connections.
func register(ctx context.Context, cfg *Config, hostname string, logger *slog.Logger) (*credentials.Credentials, error) {
	logger.Info("registering with control server",
		"server", cfg.ServerURL,
		"hostname", hostname,
	)

	// Generate key pair and CSR locally - private key never leaves the agent
	logger.Debug("generating key pair and CSR")
	csrPEM, keyPEM, err := pmcrypto.GenerateCSR(hostname)
	if err != nil {
		return nil, fmt.Errorf("generate CSR: %w", err)
	}

	// Create client options for registration
	var clientOpts []sdk.ClientOption
	if cfg.SkipVerify {
		logger.Warn("TLS verification disabled - only use for development!")
		clientOpts = append(clientOpts, sdk.WithInsecureSkipVerify())
	}

	// Register via control server RPC
	result, err := sdk.RegisterAgent(ctx, cfg.ServerURL, cfg.Token, hostname, version, csrPEM, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	logger.Info("registration successful",
		"device_id", result.DeviceID,
		"gateway_url", result.GatewayURL,
	)

	// Verify we received CA cert and signed certificate
	if len(result.CACert) == 0 || len(result.Certificate) == 0 {
		return nil, fmt.Errorf("server did not provide mTLS certificates")
	}

	return &credentials.Credentials{
		DeviceID:    result.DeviceID,
		CACert:      result.CACert,
		Certificate: result.Certificate,
		PrivateKey:  keyPEM, // Private key generated locally, never sent to server
		GatewayAddr: result.GatewayURL,
		ControlAddr: cfg.ServerURL, // Control Server URL for device auth proxy
	}, nil
}

// runAgent connects to the gateway and processes messages.
// The agent continues to run scheduled actions even when disconnected.
// If securityAlert is non-nil, it will be sent to the server after connection.
func runAgent(ctx context.Context, creds *credentials.Credentials, hostname string, h *handler.Handler, sched *scheduler.Scheduler, syncTrigger <-chan struct{}, securityAlert *pendingSecurityAlert, logger *slog.Logger) {
	// Current sync interval (can be updated by server)
	syncInterval := defaultSyncInterval

	// Track if this is the first successful sync (execute all actions)
	firstSync := true

	// Exponential backoff for reconnection
	currentBackoff := randomBackoff()

	for {
		// Reset handler connection state for new connection
		h.ResetConnection()

		var client *sdk.Client

		// Check if using http:// (h2c mode for development) or https:// (mTLS for production)
		if strings.HasPrefix(creds.GatewayAddr, "http://") {
			// Development mode: use h2c (HTTP/2 cleartext)
			logger.Debug("using h2c mode (development)")
			client = sdk.NewClient(creds.GatewayAddr,
				sdk.WithH2C(),
				sdk.WithAuth(creds.DeviceID, ""),
			)
		} else {
			// Production mode: use mTLS
			mtlsOpt, err := sdk.WithMTLSFromPEM(creds.Certificate, creds.PrivateKey, creds.CACert)
			if err != nil {
				logger.Error("failed to configure mTLS", "error", err)
				os.Exit(1)
			}
			client = sdk.NewClient(creds.GatewayAddr,
				mtlsOpt,
				sdk.WithAuth(creds.DeviceID, ""),
			)
		}

		// Create a child context for this connection session
		sessionCtx, cancelSession := context.WithCancel(ctx)

		// Wire LUKS key store to the current client for this connection session
		h.Executor().SetLuksKeyStore(&clientLuksKeyStore{client: client})

		// Wire the terminal sender so the handler's terminal session
		// goroutines can push TerminalOutput / TerminalStateChange
		// frames back via the SDK Client. The first call also starts
		// the idle-session sweeper goroutine.
		h.SetTerminalSender(client)

		// Start stream in background (opens connection, heartbeats, receives)
		streamDone := make(chan error, 1)
		go func() {
			streamDone <- client.Run(sessionCtx, hostname, version, defaultHeartbeatInterval, h)
		}()

		// Send any results stored while offline (before syncing new actions)
		syncPendingResults(sessionCtx, sched, client, logger)

		// Sync actions from server (unary RPC — stream is connecting in parallel)
		newInterval := syncActionsFromServer(sessionCtx, client, sched, firstSync, logger)
		if newInterval > 0 {
			syncInterval = newInterval
			firstSync = false
		}

		if securityAlert != nil {
			go sendSecurityAlert(sessionCtx, client, securityAlert, logger)
			securityAlert = nil
		}

		// Start periodic sync goroutine (also listens for instant sync triggers)
		syncDone := make(chan struct{})
		go func() {
			defer close(syncDone)
			periodicSync(sessionCtx, client, sched, &syncInterval, syncTrigger, logger)
		}()

		// Start result sender goroutine to send scheduled execution results to server
		resultsDone := make(chan struct{})
		go func() {
			defer close(resultsDone)
			sendScheduledResults(sessionCtx, client, sched, logger)
		}()

		// Wait for the stream to end
		connStart := time.Now()
		err := <-streamDone

		// Stop the goroutines and clear connection-dependent state
		cancelSession()
		h.Executor().SetLuksKeyStore(nil)
		<-syncDone
		<-resultsDone

		if ctx.Err() != nil {
			logger.Info("agent stopped")
			return
		}

		// Reset backoff if the connection was stable (lasted longer than the backoff interval)
		if time.Since(connStart) > currentBackoff {
			currentBackoff = randomBackoff()
		}

		logger.Error("connection lost, continuing with scheduled actions",
			"error", err,
			"backoff", currentBackoff.String(),
		)

		// Wait with exponential backoff before reconnecting
		select {
		case <-ctx.Done():
			logger.Info("agent stopped during backoff")
			return
		case <-time.After(currentBackoff):
		}

		// Increase backoff for next attempt (with cap)
		currentBackoff = time.Duration(float64(currentBackoff) * backoffFactor)
		if currentBackoff > maxBackoff {
			currentBackoff = maxBackoff
		}
	}
}

// startCertRotation runs a background loop that renews the agent's mTLS
// certificate before it expires. Renewal is attempted at 80% of the cert's
// lifetime. On failure it retries every hour.
func startCertRotation(ctx context.Context, credStore *credentials.Store, hostname string, logger *slog.Logger) {
	const retryInterval = 1 * time.Hour

	for {
		creds, err := credStore.Load()
		if err != nil {
			logger.Error("cert rotation: failed to load credentials", "error", err)
			return
		}

		// Parse current certificate to determine expiry
		block, _ := pem.Decode(creds.Certificate)
		if block == nil {
			logger.Error("cert rotation: failed to decode certificate PEM")
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			logger.Error("cert rotation: failed to parse certificate", "error", err)
			return
		}

		// Calculate renewal time at 80% of lifetime
		lifetime := cert.NotAfter.Sub(cert.NotBefore)
		renewAt := cert.NotBefore.Add(time.Duration(float64(lifetime) * 0.8))
		waitDuration := time.Until(renewAt)
		if waitDuration <= 0 {
			waitDuration = 1 * time.Minute
		}

		logger.Info("cert rotation: scheduled",
			"not_after", cert.NotAfter,
			"renew_at", renewAt,
			"wait", waitDuration.String(),
		)

		select {
		case <-ctx.Done():
			return
		case <-time.After(waitDuration):
		}

		// Generate CSR from existing private key
		csrPEM, err := pmcrypto.GenerateCSRFromKey(hostname, creds.PrivateKey)
		if err != nil {
			logger.Error("cert rotation: failed to generate CSR", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryInterval):
			}
			continue
		}

		// Build mTLS client using current (still valid) certificate.
		// The control server sits behind a public CA (Traefik +
		// Let's Encrypt in the reference deployment), so server
		// verification needs the host's system roots — the strict
		// sdk.WithMTLSFromPEM (internal CA only, as of SDK audit
		// pass) is correct for the gateway mTLS path but not for
		// this one. Application-layer identity of the agent is
		// already proven by the current certificate in the
		// RenewCertificate request body.
		mtlsOpt, err := sdk.WithMTLSFromPEMAndSystemRoots(creds.Certificate, creds.PrivateKey, creds.CACert)
		if err != nil {
			logger.Error("cert rotation: failed to configure mTLS", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryInterval):
			}
			continue
		}

		// Call RenewCertificate on the control server
		result, err := sdk.RenewCertificate(ctx, creds.ControlAddr, csrPEM, creds.Certificate, mtlsOpt)
		if err != nil {
			logger.Error("cert rotation: renewal failed, will retry", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryInterval):
			}
			continue
		}

		// Update credentials on disk with new certificate (and CA cert if rotated)
		creds.Certificate = result.Certificate
		if len(result.CACert) > 0 {
			creds.CACert = result.CACert
		}
		if err := credStore.Save(creds); err != nil {
			logger.Error("cert rotation: failed to save new certificate", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryInterval):
			}
			continue
		}

		logger.Info("cert rotation: certificate renewed successfully",
			"not_after", result.NotAfter,
		)
		// Loop to schedule next renewal based on the new cert
	}
}

// periodicSync runs a loop that periodically syncs actions from the server.
// The interval can be dynamically updated based on server response.
// Also listens on syncTrigger for instant sync requests.
func periodicSync(ctx context.Context, client *sdk.Client, sched *scheduler.Scheduler, syncInterval *time.Duration, syncTrigger <-chan struct{}, logger *slog.Logger) {
	ticker := time.NewTicker(*syncInterval)
	defer ticker.Stop()

	logger.Info("periodic sync started", "interval", syncInterval.String())

	doSync := func(reason string) {
		logger.Info("syncing actions", "reason", reason)
		newInterval := syncActionsFromServer(ctx, client, sched, false, logger)
		if newInterval > 0 && newInterval != *syncInterval {
			*syncInterval = newInterval
			ticker.Reset(*syncInterval)
			logger.Info("sync interval updated", "new_interval", syncInterval.String())
		}
	}

	for {
		select {
		case <-ctx.Done():
			logger.Debug("periodic sync stopped")
			return
		case <-ticker.C:
			doSync("periodic")
		case <-syncTrigger:
			doSync("instant action trigger")
		}
	}
}

// sendScheduledResults consumes the scheduler's Results channel and sends execution results to the server.
// This ensures that results from scheduled actions (not just server-pushed actions) are reported back.
func sendScheduledResults(ctx context.Context, client *sdk.Client, sched *scheduler.Scheduler, logger *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-sched.Results():
			if !ok {
				return
			}

			// Skip unchanged results unless this is the first execution of the action
			if !result.HasChanges && sched.HasPriorExecution(result.ActionID) {
				logger.Debug("skipping unchanged result (not first run)",
					"action_id", result.ActionID,
				)
				continue
			}

			logger.Info("sending scheduled execution result",
				"result_id", result.ResultID,
				"action_id", result.ActionID,
				"status", result.Result.Status.String(),
				"duration_ms", result.Result.DurationMs,
			)

			if err := client.SendActionResult(ctx, result.Result); err != nil {
				logger.Warn("failed to send scheduled result",
					"result_id", result.ResultID,
					"action_id", result.ActionID,
					"error", err,
				)
				// Result is already stored locally, will be synced later via syncPendingResults
				continue
			}

			// Mark result as synced in local store using the result ID (not action ID)
			if err := sched.MarkResultSynced(result.ResultID); err != nil {
				logger.Warn("failed to mark result synced",
					"result_id", result.ResultID,
					"error", err,
				)
			}
		}
	}
}

// syncActionsFromServer fetches all assigned actions from the server and updates local store.
// This replaces the local action store with the server's current assignments.
// Actions that are no longer assigned will be removed locally.
// If firstSync is true, all actions are executed; otherwise only new actions are executed.
// Returns the effective sync interval from the server (0 means use default).
func syncActionsFromServer(ctx context.Context, client *sdk.Client, sched *scheduler.Scheduler, firstSync bool, logger *slog.Logger) time.Duration {
	logger.Info("syncing actions from server", "first_sync", firstSync)

	result, err := client.SyncActions(ctx)
	if err != nil {
		logger.Warn("failed to sync actions from server", "error", err)
		return 0
	}

	if err := sched.SyncActions(ctx, result.Actions, firstSync); err != nil {
		logger.Error("failed to update local action store", "error", err)
		return 0
	}

	// Convert sync interval from minutes to duration
	var syncInterval time.Duration
	if result.SyncIntervalMinutes > 0 {
		syncInterval = time.Duration(result.SyncIntervalMinutes) * time.Minute
	} else {
		syncInterval = defaultSyncInterval
	}

	logger.Info("actions synced from server",
		"total", len(result.Actions),
		"first_sync", firstSync,
		"sync_interval", syncInterval.String(),
	)

	return syncInterval
}

// syncPendingResults sends any unsynced execution results to the server.
// This is called on connection to sync results that were stored while offline.
func syncPendingResults(ctx context.Context, sched *scheduler.Scheduler, client *sdk.Client, logger *slog.Logger) {
	results, err := sched.GetUnsyncedResults()
	if err != nil {
		logger.Warn("failed to get unsynced results", "error", err)
		return
	}

	if len(results) == 0 {
		return
	}

	logger.Info("syncing pending results", "count", len(results))

	for _, r := range results {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Skip unchanged successes unless this is the first execution of the action
		if !r.HasChanges && r.Status == pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS && sched.HasPriorExecution(r.ActionID) {
			if err := sched.MarkResultSynced(r.ID); err != nil {
				logger.Warn("failed to mark result synced", "result_id", r.ID, "error", err)
			}
			continue
		}

		logger.Info("sending offline execution result",
			"action_id", r.ActionID,
			"status", r.Status.String(),
			"executed_at", r.ExecutedAt,
			"has_changes", r.HasChanges,
		)

		// Reconstruct ActionResult from StoredResult
		actionResult := &pm.ActionResult{
			ActionId:   &pm.ActionId{Value: r.ActionID},
			Status:     r.Status,
			Error:      r.Error,
			Output:     r.Output,
			DurationMs: r.DurationMs,
		}

		// Send result to server
		if err := client.SendActionResult(ctx, actionResult); err != nil {
			logger.Warn("failed to send offline result",
				"action_id", r.ActionID,
				"error", err,
			)
			// Don't mark as synced, will retry on next connection
			continue
		}

		if err := sched.MarkResultSynced(r.ID); err != nil {
			logger.Warn("failed to mark result synced", "result_id", r.ID, "error", err)
		}
	}
}

// sendSecurityAlert sends a security alert to the server for audit logging.
// This is called in a goroutine after connection is established.
func sendSecurityAlert(ctx context.Context, client *sdk.Client, alert *pendingSecurityAlert, logger *slog.Logger) {
	// Wait a moment to ensure connection is established
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}

	logger.Info("sending security alert to server",
		"type", alert.alertType,
		"message", alert.message,
	)

	// Map alert type string to proto enum
	var alertType pm.SecurityAlertType
	switch alert.alertType {
	case "server_reassignment_attempt":
		alertType = pm.SecurityAlertType_SECURITY_ALERT_TYPE_SERVER_REASSIGNMENT_ATTEMPT
	default:
		alertType = pm.SecurityAlertType_SECURITY_ALERT_TYPE_UNSPECIFIED
	}

	protoAlert := &pm.SecurityAlert{
		Type:    alertType,
		Message: alert.message,
		Details: map[string]string{
			"requested_server":  alert.requestedServer,
			"registered_server": alert.registeredServer,
		},
	}

	if err := client.SendSecurityAlert(ctx, protoAlert); err != nil {
		logger.Warn("failed to send security alert", "error", err)
	} else {
		logger.Debug("security alert sent successfully")
	}
}

func parseFlags() *Config {
	cfg := &Config{}

	var uri string
	flag.StringVar(&uri, "uri", "", "Registration URI (power-manage://server:port?token=xxx)")
	flag.StringVar(&cfg.Token, "token", "", "Registration token for first-time setup")
	flag.StringVar(&cfg.Token, "t", "", "Registration token (shorthand)")
	flag.StringVar(&cfg.ServerURL, "server", "", "Control server URL for registration")
	flag.StringVar(&cfg.ServerURL, "s", "", "Control server URL (shorthand)")
	flag.BoolVar(&cfg.SkipVerify, "skip-verify", false, "Skip TLS verification (development only)")
	flag.StringVar(&cfg.DataDir, "data-dir", credentials.DefaultDataDir, "Data directory for credentials")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	flag.StringVar(&cfg.LogFormat, "log-format", "text", "Log format (text, json)")
	flag.Parse()

	// Check for URI as positional argument (for desktop integration)
	if uri == "" && flag.NArg() > 0 {
		arg := flag.Arg(0)
		if strings.HasPrefix(arg, "power-manage://") {
			uri = arg
		}
	}

	// Route LUKS URIs to the LUKS subcommand (power-manage://luks/...)
	if uri != "" && strings.HasPrefix(uri, "power-manage://luks/") {
		runLuksURI(uri) // runLuksURI always exits
	}

	// Parse power-manage:// URI if provided (registration URIs)
	// Format: power-manage://server:port?token=xxx[&skip-verify=true]
	if uri != "" {
		if parsed, err := parseRegistrationURI(uri); err == nil {
			// Try socket enrollment first (no sudo needed)
			if trySocketEnroll(parsed) {
				os.Exit(0)
			}
			// Fallback to direct registration (sudo/service mode)
			cfg.ServerURL = parsed.ServerURL
			cfg.Token = parsed.Token
			cfg.SkipVerify = parsed.SkipVerify
		}
	}

	// Allow environment variables to override
	if v := os.Getenv("POWER_MANAGE_TOKEN"); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv("POWER_MANAGE_SERVER"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("POWER_MANAGE_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if os.Getenv("POWER_MANAGE_SKIP_VERIFY") == "true" {
		cfg.SkipVerify = true
	}

	cfg.PrivilegeBackend = strings.ToLower(os.Getenv("POWER_MANAGE_PRIVILEGE_BACKEND"))
	cfg.ServiceBackend = strings.ToLower(os.Getenv("POWER_MANAGE_SERVICE_BACKEND"))
	cfg.EncryptionBackend = strings.ToLower(os.Getenv("POWER_MANAGE_ENCRYPTION_BACKEND"))

	return cfg
}

// registrationURI holds parsed registration URI data.
type registrationURI struct {
	ServerURL  string
	Token      string
	SkipVerify bool
}

// parseRegistrationURI parses a power-manage:// URI.
// Format: power-manage://server:port?token=xxx[&skip-verify=true][&tls=false]
// Examples:
//   - power-manage://gateway.example.com:8080?token=abc123
//   - power-manage://192.168.1.100:8080?token=abc123&skip-verify=true
//   - power-manage://gateway.example.com:8080?token=abc123&tls=false
func parseRegistrationURI(rawURI string) (*registrationURI, error) {
	// Replace power-manage:// with https:// for parsing
	// We'll determine the actual scheme from query params
	normalizedURI := strings.Replace(rawURI, "power-manage://", "https://", 1)

	parsed, err := url.Parse(normalizedURI)
	if err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	result := &registrationURI{}

	// Get query parameters
	query := parsed.Query()

	// Token is required
	result.Token = query.Get("token")
	if result.Token == "" {
		return nil, fmt.Errorf("token parameter is required in URI")
	}

	// Check for skip-verify
	if query.Get("skip-verify") == "true" {
		result.SkipVerify = true
	}

	// Determine scheme (default to https)
	scheme := "https"
	if query.Get("tls") == "false" {
		scheme = "http"
		result.SkipVerify = true // No TLS means no verification needed
	}

	// Build server URL
	result.ServerURL = fmt.Sprintf("%s://%s", scheme, parsed.Host)

	return result, nil
}

// runSetup installs the agent's privilege-escalation configuration.
// Usage: power-manage-agent setup [--user USER] [--backend sudo|doas]
//
// The backend defaults to POWER_MANAGE_PRIVILEGE_BACKEND if set,
// otherwise sudo. The --backend flag overrides both so an operator
// reinstalling a drop-in for a different backend than the running
// agent uses (e.g. prepping a dual-booted system) doesn't have to
// shuffle env vars.
func runSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	user := fs.String("user", "power-manage", "Service user name for the drop-in")
	defaultBackend := strings.ToLower(os.Getenv("POWER_MANAGE_PRIVILEGE_BACKEND"))
	if defaultBackend == "" {
		defaultBackend = "sudo"
	}
	backend := fs.String("backend", defaultBackend, "Privilege backend: sudo or doas")
	fs.Parse(args)

	switch strings.ToLower(*backend) {
	case "sudo":
		fmt.Printf("Installing sudoers drop-in for user: %s\n", *user)
		if err := setup.InstallSudoers(*user); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Sudoers installed successfully")
	case "doas":
		fmt.Printf("Installing doas drop-in for user: %s\n", *user)
		if err := setup.InstallDoas(*user); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("doas drop-in installed successfully")
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown backend %q (expected sudo or doas)\n", *backend)
		os.Exit(1)
	}
}

// runQuery executes a local osquery table query and prints results.
// Usage: power-manage-agent query <table> [--json]
func runQuery(args []string) {
	if len(args) == 0 {
		printQueryUsage()
		os.Exit(1)
	}

	tableName := args[0]
	jsonOutput := false

	// Check for --json flag
	for _, arg := range args[1:] {
		if arg == "--json" || arg == "-j" {
			jsonOutput = true
		}
	}

	// Special case: list tables
	if tableName == "tables" || tableName == "--list" || tableName == "-l" {
		printAvailableTables()
		return
	}

	// Create registry (requires osquery to be installed)
	registry, err := osquery.NewRegistry()
	if err != nil {
		if err == osquery.ErrNotInstalled {
			fmt.Fprintln(os.Stderr, "Error: osquery is not installed on this system")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Install osquery to use this feature:")
			fmt.Fprintln(os.Stderr, "  Fedora/RHEL: sudo dnf install osquery")
			fmt.Fprintln(os.Stderr, "  Debian/Ubuntu: sudo apt install osquery")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "See: https://osquery.io/downloads/official")
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}

	result, err := registry.Query(&pm.OSQuery{
		QueryId: "cli-query",
		Table:   tableName,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !result.Success {
		fmt.Fprintf(os.Stderr, "Query failed: %s\n", result.Error)
		os.Exit(1)
	}

	if len(result.Rows) == 0 {
		fmt.Println("No results")
		return
	}

	if jsonOutput {
		printQueryResultsJSON(result.Rows)
	} else {
		printQueryResultsTable(result.Rows)
	}
}

func printQueryUsage() {
	fmt.Println("Usage: power-manage-agent query <table> [--json]")
	fmt.Println()
	fmt.Println("Query system information using the installed osquery binary.")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  query tables          List available tables")
	fmt.Println("  query <table>         Query a specific table")
	fmt.Println("  query <table> --json  Output results as JSON")
	fmt.Println()
	fmt.Println("Note: Requires osquery to be installed on the system.")
	fmt.Println("See: https://osquery.io/downloads/official")
}

func printAvailableTables() {
	// Check if osquery is installed
	if !osquery.IsInstalled() {
		fmt.Fprintln(os.Stderr, "Error: osquery is not installed on this system")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Install osquery to use this feature:")
		fmt.Fprintln(os.Stderr, "  Fedora/RHEL: sudo dnf install osquery")
		fmt.Fprintln(os.Stderr, "  Debian/Ubuntu: sudo apt install osquery")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "See: https://osquery.io/downloads/official")
		os.Exit(1)
	}

	registry, err := osquery.NewRegistry()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	tables, err := registry.ListTables()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing tables: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Available osquery tables:")
	for _, table := range tables {
		fmt.Printf("  %s\n", table)
	}
	fmt.Printf("\nTotal: %d tables\n", len(tables))
}

func printQueryResultsJSON(rows []*pm.OSQueryRow) {
	// Convert to slice of maps for JSON output
	data := make([]map[string]string, len(rows))
	for i, row := range rows {
		data[i] = row.Data
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}

func printQueryResultsTable(rows []*pm.OSQueryRow) {
	if len(rows) == 0 {
		return
	}

	// Collect all unique keys across all rows
	keySet := make(map[string]bool)
	for _, row := range rows {
		for k := range row.Data {
			keySet[k] = true
		}
	}

	// Sort keys for consistent output
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	// Simple sort
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}

	// Use tabwriter for aligned output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Print header
	for i, k := range keys {
		if i > 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, strings.ToUpper(k))
	}
	fmt.Fprintln(w)

	// Print separator
	for i, k := range keys {
		if i > 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, strings.Repeat("-", len(k)))
	}
	fmt.Fprintln(w)

	// Print rows
	for _, row := range rows {
		for i, k := range keys {
			if i > 0 {
				fmt.Fprint(w, "\t")
			}
			fmt.Fprint(w, row.Data[k])
		}
		fmt.Fprintln(w)
	}

	w.Flush()
}

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

	// Connect to gateway via mTLS
	var clientOpts []sdk.ClientOption
	if strings.HasPrefix(creds.GatewayAddr, "http://") {
		clientOpts = append(clientOpts, sdk.WithH2C(), sdk.WithAuth(creds.DeviceID, ""))
	} else {
		mtlsOpt, err := sdk.WithMTLSFromPEM(creds.Certificate, creds.PrivateKey, creds.CACert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to configure mTLS: %v\n", err)
			os.Exit(1)
		}
		clientOpts = append(clientOpts, mtlsOpt, sdk.WithAuth(creds.DeviceID, ""))
	}
	client := sdk.NewClient(creds.GatewayAddr, clientOpts...)

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

	// Step 2: Create mTLS client
	var client *sdk.Client
	if strings.HasPrefix(creds.GatewayAddr, "http://") {
		client = sdk.NewClient(creds.GatewayAddr,
			sdk.WithH2C(),
			sdk.WithAuth(creds.DeviceID, ""),
		)
	} else {
		mtlsOpt, err := sdk.WithMTLSFromPEM(creds.Certificate, creds.PrivateKey, creds.CACert)
		if err != nil {
			logger.Error("self-test: failed to configure mTLS", "error", err)
			return 1
		}
		client = sdk.NewClient(creds.GatewayAddr,
			mtlsOpt,
			sdk.WithAuth(creds.DeviceID, ""),
		)
	}

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

// runTTY manages the device-local TTY enable/disable toggle.
// Usage:
//
//	power-manage-agent tty enable
//	power-manage-agent tty disable
//	power-manage-agent tty status
//
// The toggle is stored in the agent's SQLite database. The CLI must be
// run as the power-manage user (the owner of the agent's data dir) or
// as root via sudo — a regular user cannot escalate into the toggle
// without first escalating to one of those identities.
func runTTY(args []string) int {
	fs := flag.NewFlagSet("tty", flag.ExitOnError)
	dataDir := fs.String("data-dir", credentials.DefaultDataDir, "Agent data directory")

	if len(args) == 0 {
		printTTYUsage()
		return 1
	}

	sub := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}

	switch sub {
	case "-h", "--help", "help":
		printTTYUsage()
		return 0
	case "enable", "disable", "status":
		// handled below
	default:
		fmt.Fprintf(os.Stderr, "unknown tty subcommand: %s\n", sub)
		printTTYUsage()
		return 1
	}

	// Require root for mutating subcommands. The tty.enabled row in the
	// agent's SQLite DB is owned by the agent service user; another
	// unprivileged local user must not be able to flip the flag for a
	// user they aren't. Root-only enforces that — sudo or an equivalent
	// privilege backend is the only path to the mutator.
	//
	// An earlier revision also required the call to originate from an
	// interactive TTY so a server-dispatched `ACTION_TYPE_SHELL` couldn't
	// flip the flag remotely. That gate was dropped in this revision:
	// the `script(1)` utility routes around it in one line (pty
	// allocation makes the stdin check pass), so the gate only added
	// operational friction without providing real defence-in-depth. The
	// server-side answer to "who can grant terminal access on which
	// device" belongs in the permission model (RBAC + the fleet-wide
	// distribution of shell actions), not in a terminal-shape check on
	// the agent CLI.
	if sub == "enable" || sub == "disable" {
		if os.Geteuid() != 0 {
			fmt.Fprintf(os.Stderr, "Error: tty %s must be run as root (try: sudo power-manage-agent tty %s)\n", sub, sub)
			return 1
		}
	}

	st, err := store.New(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: open agent store: %v\n", err)
		return 1
	}
	defer st.Close()

	switch sub {
	case "enable":
		if err := st.SetTTYEnabled(true); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Println("TTY enabled.")
		return 0
	case "disable":
		if err := st.SetTTYEnabled(false); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		fmt.Println("TTY disabled.")
		return 0
	case "status":
		enabled, err := st.IsTTYEnabled()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		if enabled {
			fmt.Println("enabled")
			return 0
		}
		fmt.Println("disabled")
		return 1
	}
	return 1
}

func printTTYUsage() {
	fmt.Fprintln(os.Stderr, "usage: power-manage-agent tty {enable|disable|status} [--data-dir=PATH]")
}

// runEnroll handles the "enroll" subcommand.
// Usage: power-manage-agent enroll -server=URL -token=TOKEN
//
//	power-manage-agent enroll 'power-manage://server:port?token=xxx'
func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	token := fs.String("token", "", "Registration token")
	server := fs.String("server", "", "Control server URL")
	skipVerify := fs.Bool("skip-verify", false, "Skip TLS verification")
	socketPath := fs.String("socket", deviceauth.EnrollSocketPath, "Agent enrollment socket")
	fs.Parse(args)

	// Accept power-manage:// URI as positional arg
	if fs.NArg() > 0 {
		arg := fs.Arg(0)
		if strings.HasPrefix(arg, "power-manage://") {
			if parsed, err := parseRegistrationURI(arg); err == nil {
				*server = parsed.ServerURL
				*token = parsed.Token
				*skipVerify = parsed.SkipVerify
			} else {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		}
	}

	if *token == "" || *server == "" {
		fmt.Fprintln(os.Stderr, "error: -server and -token are required")
		fmt.Fprintln(os.Stderr, "usage: power-manage-agent enroll -server=URL -token=TOKEN")
		fmt.Fprintln(os.Stderr, "   or: power-manage-agent enroll 'power-manage://server:port?token=xxx'")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Connect to the enrollment socket
	httpClient := unixSocketHTTPClient(*socketPath)
	client := pmv1connect.NewDeviceAuthServiceClient(httpClient, "http://localhost")

	// Check enrollment status first
	status, err := client.GetEnrollmentStatus(ctx, connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot connect to agent enrollment socket at %s\n", *socketPath)
		fmt.Fprintln(os.Stderr, "Is the agent service running? Check: systemctl status power-manage-agent")
		os.Exit(1)
	}

	if status.Msg.Enrolled {
		fmt.Printf("Agent is already enrolled (device ID: %s)\n", status.Msg.DeviceId)
		return
	}

	// Enroll via socket
	resp, err := client.Enroll(ctx, connect.NewRequest(&pm.EnrollRequest{
		ServerUrl:  *server,
		Token:      *token,
		SkipVerify: *skipVerify,
	}))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: enrollment failed: %v\n", err)
		os.Exit(1)
	}

	if !resp.Msg.Success {
		fmt.Fprintf(os.Stderr, "error: enrollment failed: %s\n", resp.Msg.Error)
		os.Exit(1)
	}

	fmt.Printf("Enrolled successfully. Device ID: %s\n", resp.Msg.DeviceId)
}

// trySocketEnroll attempts to enroll via the agent's enrollment socket.
// Returns true if enrollment succeeded (caller should exit).
func trySocketEnroll(parsed *registrationURI) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	httpClient := unixSocketHTTPClient(deviceauth.EnrollSocketPath)
	client := pmv1connect.NewDeviceAuthServiceClient(httpClient, "http://localhost")

	// Check if the enrollment socket is available
	_, err := client.GetEnrollmentStatus(ctx, connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	if err != nil {
		// Socket not available — fall back to direct registration
		return false
	}

	resp, err := client.Enroll(ctx, connect.NewRequest(&pm.EnrollRequest{
		ServerUrl:  parsed.ServerURL,
		Token:      parsed.Token,
		SkipVerify: parsed.SkipVerify,
	}))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: socket enrollment failed: %v\n", err)
		return false
	}

	if !resp.Msg.Success {
		fmt.Fprintf(os.Stderr, "error: socket enrollment failed: %s\n", resp.Msg.Error)
		return false
	}

	fmt.Printf("Enrolled successfully via agent socket. Device ID: %s\n", resp.Msg.DeviceId)
	return true
}

// unixSocketHTTPClient returns an HTTP client that dials the given unix socket.
func unixSocketHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
}
