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
	// DefaultSocketPath is the default unix socket path for the device auth service.
	DefaultSocketPath = "/run/pm-agent/auth.sock"
)

// Server runs the DeviceAuthService over a unix socket.
type Server struct {
	handler    *Handler
	socketPath string
	logger     *slog.Logger
	httpServer *http.Server
}

// NewServer creates a new device auth socket server.
func NewServer(handler *Handler, socketPath string, logger *slog.Logger) *Server {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &Server{
		handler:    handler,
		socketPath: socketPath,
		logger:     logger,
	}
}

// Start starts the unix socket server. It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
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

	// Set socket permissions: root can read/write, pm-auth group can read/write
	if err := os.Chmod(s.socketPath, 0660); err != nil {
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

	s.logger.Info("device auth service listening", "socket", s.socketPath)

	// Shutdown on context cancellation
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("device auth server shutdown error", "error", err)
		}
		os.Remove(s.socketPath)
	}()

	if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
