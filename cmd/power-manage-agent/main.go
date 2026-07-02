// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/manchtools/power-manage-sdk/logging"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/verify"
	"github.com/manchtools/power-manage/agent/internal/credentials"
	"github.com/manchtools/power-manage/agent/internal/deviceauth"
	"github.com/manchtools/power-manage/agent/internal/executor"
	"github.com/manchtools/power-manage/agent/internal/handler"
	"github.com/manchtools/power-manage/agent/internal/luksd"
	"github.com/manchtools/power-manage/agent/internal/scheduler"
	"github.com/manchtools/power-manage/agent/internal/store"
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

// Config holds the agent configuration.
type Config struct {
	// Registration
	Token     string
	ServerURL string

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

func main() {
	// Check for subcommands before parsing flags
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Printf("power-manage-agent %s\n", version)
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
	resolvedBackend, err := applyBackendOverrides(cfg, logger)
	if err != nil {
		logger.Error("backend validation failed", "error", err)
		os.Exit(1)
	}
	// Build the one process-wide exec.Runner from the resolved privilege backend
	// and inject it into every capability Manager (no global privilege state).
	runner, err := sysexec.NewRunner(resolvedBackend)
	if err != nil {
		logger.Error("failed to build privilege runner", "error", err)
		os.Exit(1)
	}

	// Clean up stale update state from a previous cycle (if any).
	executor.CheckStartupUpdateState(cfg.DataDir, logger, time.Now)

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

		// Ignore registration token if already registered. Promoted
		// from Debug to Info because operators who re-run with a
		// fresh token expecting re-enrollment otherwise get no
		// feedback about why nothing happened. Audit F037.
		if cfg.Token != "" {
			logger.Info("ignoring registration token — agent is already registered; delete credentials.enc first to re-enroll")
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

	// Start the LUKS passphrase daemon (WS6 #1/#19). It listens on a
	// world-connectable unix socket; an unprivileged user runs
	// `power-manage-agent luks set-passphrase` and the root agent performs
	// the cryptsetup work with its OWN credentials, authorized by the
	// server-issued token — replacing the old NOPASSWD sudoers rule +
	// attacker-controllable --data-dir. The gateway session is wired in
	// per connection (SetSession/ClearSession) inside runAgent.
	luksDaemon := luksd.NewDaemon(luksd.DefaultSocketPath, actionStore, luksd.NewSysencEnroller(), logger)
	go func() {
		if err := luksDaemon.Start(ctx); err != nil {
			logger.Error("LUKS passphrase daemon failed", "error", err)
		}
	}()

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
	exec := executor.NewExecutor(actionVerifier, runner)
	exec.SetStore(actionStore)
	// The agent's own device ID is part of the LPS seal context so control
	// unseals each rotated password into the right (device, action, user) record.
	exec.SetDeviceID(creds.DeviceID)
	sched := scheduler.New(actionStore, exec, logger)
	exec.SetActionStore(sched)

	// Start the scheduler in a goroutine
	go sched.Start(ctx)

	// Create sync trigger channel for instant SYNC actions
	syncTrigger := make(chan struct{}, 1)

	// Create handler with scheduler integration
	h := handler.NewHandler(logger, exec, sched, actionStore, syncTrigger)

	// Enable action-based agent self-update. The binary path is
	// resolved at runtime via os.Executable() so the self-update
	// targets the actually-running binary, not a hardcoded
	// install location. Operators who install with `install.sh
	// --binary /opt/bin/...` get correct in-place updates instead
	// of a silently-wrong overwrite of /usr/local/bin/.
	//
	// Symlink note: os.Executable resolves symlinks on Linux, so
	// if the agent was launched via a symlink chain (e.g.
	// /usr/bin/power-manage-agent -> /opt/pm/current/bin/power-manage-agent)
	// the self-update replaces the symlink TARGET, leaving the
	// symlink itself intact. That matches the typical "rotate
	// /opt/pm/current/" deployment pattern; if an operator
	// instead intends "update by repointing the symlink" they
	// should rely on package management rather than self-update.
	binaryPath, err := os.Executable()
	if err != nil {
		// os.Executable can fail on platforms that don't expose
		// /proc/self/exe symlink semantics. The previous behaviour
		// silently fell back to /usr/local/bin/power-manage-agent
		// — but on a non-standard install that hard-codes the
		// wrong target and self-update would later overwrite some
		// unrelated file. Refuse to enable self-update instead, so
		// the operator notices and can intervene. Audit F046.
		logger.Error("os.Executable failed; self-update DISABLED for this process",
			"error", err,
			"remediation", "run from a path where os.Executable can resolve /proc/self/exe, or disable self-update upstream")
	} else {
		exec.SetUpdateConfig(&executor.AgentUpdateConfig{
			Version:    version,
			DataDir:    cfg.DataDir,
			BinaryPath: binaryPath,
			Shutdown:   cancel,
		})
	}

	// Start certificate rotation goroutine
	if creds.ControlAddr != "" {
		go startCertRotation(ctx, credStore, hostname, logger, time.Now)
	}

	// Run the agent
	logger.Info("starting agent",
		"gateway", creds.GatewayAddr,
		"device_id", creds.DeviceID,
		"hostname", hostname,
		"version", version,
	)

	runAgent(ctx, credStore, creds, hostname, h, sched, syncTrigger, cfg.pendingSecurityAlert, luksDaemon, logger, time.Now)

	// Join the scheduler goroutine BEFORE the deferred actionStore.Close()
	// runs (WS14 #9). Stop() blocks until the Start loop returns; execution is
	// synchronous in that loop, so any in-flight action's RecordExecution has
	// committed to the store before we close it — no lost result / use-after-close
	// on SIGTERM.
	sched.Stop()

	// Tear down any live terminal sessions (WS16 #5): a session left open at
	// shutdown would leave its pm-tty shell activated and its temp home on
	// disk. Use a fresh bounded ctx — the run ctx may already be cancelled by
	// the shutdown signal, which would abort the usermod shell-revert.
	teardownCtx, cancelTeardown := context.WithTimeout(context.Background(), 30*time.Second)
	h.CloseAllTerminals(teardownCtx)
	cancelTeardown()

	// Stop background goroutines started during runAgent. The
	// terminal sweeper would otherwise outlive the agent process in
	// any non-os.Exit shutdown path (audit F004).
	h.StopTerminalSweeper()
}

func parseFlags() *Config {
	cfg := &Config{}

	// Subcommands are dispatched in main() before flags are parsed, so the
	// default flag usage (flags only) never mentions them. List them here so
	// `power-manage-agent --help` shows the full surface (notably `tty`, which
	// operators otherwise can't discover).
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "power-manage-agent — Power Manage device agent")
		fmt.Fprintln(out, "\nUsage:")
		fmt.Fprintln(out, "  power-manage-agent [flags]           run the agent (default)")
		fmt.Fprintln(out, "  power-manage-agent <command> [args]  run a subcommand")
		fmt.Fprintln(out, "\nSubcommands:")
		fmt.Fprintln(out, "  enroll      enroll this device with a control server (token or power-manage:// URI)")
		fmt.Fprintln(out, "  tty         toggle the device-local remote-terminal gate (enable|disable|status)")
		fmt.Fprintln(out, "  luks        LUKS passphrase operations")
		fmt.Fprintln(out, "  query       run a local osquery query")
		fmt.Fprintln(out, "  self-test   run agent self-diagnostics")
		fmt.Fprintln(out, "  version     print the agent version")
		fmt.Fprintln(out, "\nFlags (default run mode):")
		flag.PrintDefaults()
	}

	var uri string
	flag.StringVar(&uri, "uri", "", "Registration URI (power-manage://server:port?token=xxx)")
	flag.StringVar(&cfg.Token, "token", "", "Registration token for first-time setup")
	flag.StringVar(&cfg.Token, "t", "", "Registration token (shorthand)")
	flag.StringVar(&cfg.ServerURL, "server", "", "Control server URL for registration")
	flag.StringVar(&cfg.ServerURL, "s", "", "Control server URL (shorthand)")
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

	// Any remaining power-manage:// URI here is a REGISTRATION URI (server+token)
	// arriving via the bare-binary / desktop URI-handler path (luks URIs already
	// exited above). REFUSE it (WS7): a browser-triggered
	// power-manage://<server>?token=... must not silently enroll this device into
	// an attacker-controlled backend. Enrollment must be an explicit,
	// operator-initiated action via the `enroll` subcommand, which accepts the
	// same URI.
	if registrationURIRefusedByHandler(uri) {
		fmt.Fprintln(os.Stderr, "refusing to enroll from a URI handler: enrollment must be explicit. Run:")
		fmt.Fprintf(os.Stderr, "  power-manage-agent enroll '%s'\n", uri)
		os.Exit(1)
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

	cfg.PrivilegeBackend = strings.ToLower(os.Getenv("POWER_MANAGE_PRIVILEGE_BACKEND"))
	cfg.ServiceBackend = strings.ToLower(os.Getenv("POWER_MANAGE_SERVICE_BACKEND"))
	cfg.EncryptionBackend = strings.ToLower(os.Getenv("POWER_MANAGE_ENCRYPTION_BACKEND"))

	return cfg
}

// registrationURI holds parsed registration URI data.
