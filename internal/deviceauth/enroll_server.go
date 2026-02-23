package deviceauth

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
)

const (
	// EnrollSocketPath is the unix socket for enrollment requests.
	// Mode 0666 so any local user can connect (token is the authorization).
	EnrollSocketPath = "/run/pm-agent/enroll.sock"
)

// EnrollServer runs the enrollment service over a unix socket.
type EnrollServer struct {
	handler    *EnrollHandler
	socketPath string
	logger     *slog.Logger
	httpServer *http.Server
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

	// Set socket permissions: world-readable/writable so any local user can enroll.
	// The registration token is the authorization mechanism.
	if err := os.Chmod(s.socketPath, 0666); err != nil {
		listener.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Create HTTP mux with Connect-RPC handler
	mux := http.NewServeMux()
	path, handler := pmv1connect.NewDeviceAuthServiceHandler(s.handler)
	mux.Handle(path, handler)

	s.httpServer = &http.Server{
		Handler:     mux,
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	s.logger.Info("enrollment service listening", "socket", s.socketPath)

	// Shutdown on context cancellation
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("enrollment server shutdown error", "error", err)
		}
		os.Remove(s.socketPath)
	}()

	if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the enrollment server.
func (s *EnrollServer) Shutdown() {
	if s.httpServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(shutdownCtx)
		os.Remove(s.socketPath)
	}
}
