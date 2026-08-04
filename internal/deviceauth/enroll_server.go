package deviceauth

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1/powermanagev1connect"
)

const (
	// EnrollSocketPath is the unix socket for enrollment requests.
	// Mode 0600 plus an SO_PEERCRED check restrict it to a local process
	// running as the agent's own uid (root under the shipped unit) — any
	// other local uid is refused. This authorizes by OS identity, not human
	// intent: a root-owned service could also connect, so enrollment stays a
	// privileged local operation rather than something any local user can do.
	EnrollSocketPath = "/run/pm-agent/enroll.sock"
)

// EnrollServer runs the enrollment service over a unix socket.
type EnrollServer struct {
	handler      *EnrollHandler
	socketPath   string
	logger       *slog.Logger
	httpServer   *http.Server
	shutdownOnce sync.Once
}

// NewEnrollServer creates a new enrollment socket server.
func NewEnrollServer(handler *EnrollHandler, socketPath string, logger *slog.Logger) *EnrollServer {
	if socketPath == "" {
		socketPath = EnrollSocketPath
	}
	return &EnrollServer{
		handler:    handler,
		socketPath: socketPath,
		logger:     logger,
	}
}

// Start starts the enrollment socket server. It blocks until ctx is cancelled.
func (s *EnrollServer) Start(ctx context.Context) error {
	// Ensure parent directory exists
	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create socket directory %s: %w", dir, err)
	}

	// Remove stale socket file
	os.Remove(s.socketPath)

	// Create unix listener
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}

	// Restrict the socket to its owner (the agent's uid, root under the
	// shipped unit). Enrollment authorizes a control plane to command this
	// host, so the caller must be a local process running as the agent's uid,
	// not any local user; a world-writable socket would let any unprivileged
	// local user enroll the root agent into an attacker-controlled control
	// plane.
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		_ = listener.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Authenticate the connecting process by its OS identity: only the
	// agent's own uid may enroll. This is the load-bearing check — file mode
	// alone can be widened by a privileged actor — and it fails closed when
	// peer credentials cannot be read. The token/URL/pin validation in the
	// handler remains as defense in depth.
	listener = newPeerCredListener(listener, s.logger)

	// Create HTTP mux with Connect-RPC handler
	mux := http.NewServeMux()
	path, handler := powermanagev1connect.NewDeviceAuthServiceHandler(s.handler)
	mux.Handle(path, handler)

	s.httpServer = &http.Server{
		Handler: mux,
		// BaseContext deliberately omitted: per-request contexts must
		// outlive the supervising ctx so Shutdown() can drain in-flight
		// enrollment requests instead of cancelling them mid-CSR-sign
		// when the agent receives SIGTERM.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	s.logger.Info("enrollment service listening", "socket", s.socketPath)

	// Shutdown on context cancellation
	go func() {
		<-ctx.Done()
		s.Shutdown()
	}()

	if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the enrollment server.
func (s *EnrollServer) Shutdown() {
	s.shutdownOnce.Do(func() {
		if s.httpServer != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.httpServer.Shutdown(shutdownCtx)
			os.Remove(s.socketPath)
		}
	})
}
