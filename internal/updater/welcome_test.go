package updater

import (
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestHandleWelcome_NoUpdate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Same version — no update needed.
	err := HandleWelcome(context.Background(), WelcomeConfig{
		LatestVersion:  "2026.04.1",
		UpdateURL:      "https://example.com/agent",
		UpdateChecksum: "abc123",
		CurrentVersion: "2026.04.1",
		DataDir:        t.TempDir(),
		BinaryPath:     "/usr/local/bin/power-manage-agent",
		ServiceName:    "power-manage-agent",
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("HandleWelcome: %v", err)
	}
}

func TestHandleWelcome_EmptyVersion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	err := HandleWelcome(context.Background(), WelcomeConfig{
		LatestVersion:  "",
		UpdateURL:      "",
		UpdateChecksum: "",
		CurrentVersion: "2026.04.1",
		DataDir:        t.TempDir(),
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("HandleWelcome: %v", err)
	}
}

func TestHandleWelcome_EmptyURL(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	err := HandleWelcome(context.Background(), WelcomeConfig{
		LatestVersion:  "2026.04.2",
		UpdateURL:      "",
		UpdateChecksum: "",
		CurrentVersion: "2026.04.1",
		DataDir:        t.TempDir(),
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("HandleWelcome: %v", err)
	}
}

func TestHandleWelcome_Cooldown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	dir := t.TempDir()

	// Write a cooldown for the target version.
	if err := WriteCooldown(dir, "2026.04.2", 1*60*60*1e9); err != nil { // 1 hour in nanoseconds
		t.Fatalf("WriteCooldown: %v", err)
	}

	err := HandleWelcome(context.Background(), WelcomeConfig{
		LatestVersion:  "2026.04.2",
		UpdateURL:      "https://example.com/agent",
		UpdateChecksum: "abc123",
		CurrentVersion: "2026.04.1",
		DataDir:        dir,
		BinaryPath:     "/usr/local/bin/power-manage-agent",
		ServiceName:    "power-manage-agent",
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("HandleWelcome: %v", err)
	}
	// No download should have been attempted since version is cooling down.
}
