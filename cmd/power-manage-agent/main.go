// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	"github.com/manchtools/power-manage/agent/internal/deviceauth"
	"github.com/manchtools/power-manage/agent/internal/executor"
	"github.com/manchtools/power-manage/agent/internal/handler"
	"github.com/manchtools/power-manage/agent/internal/osquery"
	"github.com/manchtools/power-manage/agent/internal/scheduler"
	"github.com/manchtools/power-manage/agent/internal/setup"
	"github.com/manchtools/power-manage/agent/internal/store"
	"github.com/manchtools/power-manage/agent/internal/verify"
	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
	sdk "github.com/manchtools/power-manage/sdk/go"
	sysluks "github.com/manchtools/power-manage/sdk/go/sys/luks"

	"golang.org/x/term"
)

// version is set at build time via -ldflags.
var version = "dev"

const (
	defaultHeartbeatInterval = 30 * time.Second
	defaultSyncInterval      = 30 * time.Minute

	// Exponential backoff constants for reconnection
	initialBackoff = 1 * time.Second
	maxBackoff     = 5 * time.Minute
	backoffFactor  = 2.0
)

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
		}
	}

	cfg := parseFlags()

	// Setup logger
	logger := setupLogger(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)
	logger.Info("logger initialized", "level", cfg.LogLevel, "format", cfg.LogFormat)

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
	h := handler.NewHandler(logger, exec, sched, syncTrigger)

	// Start local device auth socket server (for PAM/NSS)
	if creds.ControlAddr != "" {
		startDeviceAuthServer(ctx, creds, logger)
	}

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
	csrPEM, keyPEM, err := credentials.GenerateCSR(hostname)
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
	currentBackoff := initialBackoff

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
			currentBackoff = initialBackoff
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
		csrPEM, err := credentials.GenerateCSRFromKey(hostname, creds.PrivateKey)
		if err != nil {
			logger.Error("cert rotation: failed to generate CSR", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryInterval):
			}
			continue
		}

		// Build mTLS client using current (still valid) certificate
		mtlsOpt, err := sdk.WithMTLSFromPEM(creds.Certificate, creds.PrivateKey, creds.CACert)
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

// startDeviceAuthServer starts the local device auth socket server in a
// background goroutine. The server exposes the DeviceAuthService over a unix
// socket so PAM/NSS modules can authenticate users via the PM Control Server.
func startDeviceAuthServer(ctx context.Context, creds *credentials.Credentials, logger *slog.Logger) {
	// Build an HTTP client that can talk to the Control Server.
	// Use mTLS if the agent has certificates, plain HTTP for dev (http://).
	var httpClient *http.Client
	if strings.HasPrefix(creds.ControlAddr, "http://") {
		httpClient = &http.Client{
			Transport: &http2.Transport{
				AllowHTTP: true,
				DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				},
			},
		}
	} else {
		cert, err := tls.X509KeyPair(creds.Certificate, creds.PrivateKey)
		if err != nil {
			logger.Error("device auth: failed to parse mTLS certs", "error", err)
			return
		}
		caPool, err := x509.SystemCertPool()
		if err != nil {
			caPool = x509.NewCertPool()
		}
		caPool.AppendCertsFromPEM(creds.CACert)
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS13,
			},
		}
		http2.ConfigureTransport(transport)
		httpClient = &http.Client{Transport: transport}
	}

	handler := deviceauth.NewHandler(creds.DeviceID, creds.ControlAddr, httpClient, logger)
	server := deviceauth.NewServer(handler, deviceauth.DefaultSocketPath, logger)

	go func() {
		if err := server.Start(ctx); err != nil {
			logger.Error("device auth server failed", "error", err)
		}
	}()
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

			// Only send results that have changes (or are failures)
			if !result.HasChanges {
				logger.Debug("skipping result without changes",
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

		// Skip results without changes (unless they failed)
		if !r.HasChanges && r.Status == pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
			// Mark as synced since we don't need to report no-change successes
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
	flag.StringVar(&cfg.ServerURL, "server", "", "Control server URL for registration")
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

func setupLogger(level, format string) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	var slogHandler slog.Handler
	if format == "json" {
		slogHandler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		slogHandler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(slogHandler)
}

// runSetup installs the agent's sudoers configuration.
// Usage: power-manage-agent setup [--user USER]
func runSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	user := fs.String("user", "power-manage", "Service user name for sudoers")
	fs.Parse(args)

	fmt.Printf("Installing sudoers for user: %s\n", *user)
	if err := setup.InstallSudoers(*user); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Sudoers installed successfully")
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
	var complexity sysluks.Complexity
	switch result.Complexity {
	case pm.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_ALPHANUMERIC:
		complexity = sysluks.ComplexityAlphanumeric
	case pm.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX:
		complexity = sysluks.ComplexityComplex
	default:
		complexity = sysluks.ComplexityNone
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

	recentHashes, _ := agentStore.GetLuksPassphraseHashes(result.ActionID)

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
		if validationErr := sysluks.ValidatePassphrase(candidate, minLength, complexity); validationErr != "" {
			if remaining > 0 {
				fmt.Printf("%s %d attempt(s) remaining.\n", validationErr, remaining)
			}
			continue
		}

		// Check reuse
		if sysluks.IsRecentlyUsed(candidate, recentHashes) {
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

	hostname, _ := os.Hostname()
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
			if err := sysluks.WipeTPM(ctx, devicePath, managedKey); err != nil {
				fmt.Fprintf(os.Stderr, "error: failed to wipe TPM key: %v\n", err)
				os.Exit(1)
			}
		case "user_passphrase":
			if err := sysluks.KillSlot(ctx, devicePath, 7, managedKey); err != nil {
				fmt.Fprintf(os.Stderr, "error: failed to remove existing passphrase: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Add user passphrase to slot 7
	fmt.Println("Setting LUKS passphrase...")
	if err := sysluks.AddKeyToSlot(ctx, devicePath, 7, managedKey, passphrase); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to set passphrase: %v\nManaged key may have been rotated.\n", err)
		os.Exit(1)
	}

	// Update local state
	agentStore.SetLuksDeviceKeyType(result.ActionID, "user_passphrase")

	// Store passphrase hash for reuse prevention (keeps last 3)
	agentStore.AddLuksPassphraseHash(result.ActionID, sysluks.HashPassphrase(passphrase))

	fmt.Println("LUKS passphrase set successfully.")
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
