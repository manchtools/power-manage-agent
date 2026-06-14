// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/agent/internal/deviceauth"
	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
)

// parseRegistrationURI parses a power-manage:// URI.
// Format: power-manage://server:port?token=xxx
// Examples:
//   - power-manage://gateway.example.com:8080?token=abc123
//
// TLS verification is always enforced. The previous `skip-verify=true`
// and `tls=false` query parameters were removed because bypassing
// TLS during initial registration enables MITM attacks that can
// substitute the gateway URL and a malicious certificate before the
// agent has any trust anchor of its own.
func parseRegistrationURI(rawURI string) (*registrationURI, error) {
	// Replace power-manage:// with https:// for parsing.
	normalizedURI := strings.Replace(rawURI, "power-manage://", "https://", 1)

	parsed, err := url.Parse(normalizedURI)
	if err != nil {
		return nil, fmt.Errorf("invalid URI: %w", err)
	}

	// Token is required.
	token := parsed.Query().Get("token")
	if token == "" {
		return nil, fmt.Errorf("token parameter is required in URI")
	}

	return &registrationURI{
		ServerURL: fmt.Sprintf("https://%s", parsed.Host),
		Token:     token,
		// Optional out-of-band CA fingerprint pin. Any tls=/skip-verify=
		// query params are intentionally ignored — ServerURL is always
		// normalized to https, there is no TLS-bypass path.
		Pin: parsed.Query().Get("pin"),
	}, nil
}

// resolveEnrollToken resolves the registration token, preferring secure
// delivery: a -token-file read from disk, then the PM_REGISTRATION_TOKEN
// environment variable, and only as a last resort the -token argv flag —
// which is warned against because process arguments are world-readable
// via /proc/<pid>/cmdline (finding #3). Returns "" when no source
// provided a token.
func resolveEnrollToken(flagToken, tokenFile, envToken string) (string, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file %s: %w", tokenFile, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if envToken != "" {
		return strings.TrimSpace(envToken), nil
	}
	if flagToken != "" {
		fmt.Fprintln(os.Stderr, "warning: passing -token on the command line is insecure (visible in /proc/<pid>/cmdline); prefer -token-file or the PM_REGISTRATION_TOKEN environment variable")
		return strings.TrimSpace(flagToken), nil
	}
	return "", nil
}

// runEnroll handles the "enroll" subcommand.
// Usage: power-manage-agent enroll -server=URL -token=TOKEN
//
//	power-manage-agent enroll 'power-manage://server:port?token=xxx'
func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	token := fs.String("token", "", "Registration token (INSECURE on argv; prefer -token-file or PM_REGISTRATION_TOKEN)")
	tokenFile := fs.String("token-file", "", "Path to a file containing the registration token (preferred over -token)")
	server := fs.String("server", "", "Control server URL")
	pin := fs.String("pin", "", "Optional CA fingerprint pin (SHA-256 hex of the control CA) verified before trusting the server CA")
	socketPath := fs.String("socket", deviceauth.EnrollSocketPath, "Agent enrollment socket")
	fs.Parse(args)

	caPin := *pin
	fromURI := false

	// Accept power-manage:// URI as positional arg
	if fs.NArg() > 0 {
		arg := fs.Arg(0)
		if strings.HasPrefix(arg, "power-manage://") {
			parsed, err := parseRegistrationURI(arg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			*server = parsed.ServerURL
			*token = parsed.Token
			if parsed.Pin != "" {
				caPin = parsed.Pin
			}
			fromURI = true
		}
	}

	// Resolve the token. The URI carries its own token; otherwise prefer
	// the secure -token-file / PM_REGISTRATION_TOKEN sources over -token
	// argv (which leaks via /proc/<pid>/cmdline, #3).
	resolvedToken := *token
	if !fromURI {
		rt, err := resolveEnrollToken(*token, *tokenFile, os.Getenv("PM_REGISTRATION_TOKEN"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		resolvedToken = rt
	}

	if resolvedToken == "" || *server == "" {
		fmt.Fprintln(os.Stderr, "error: a control server URL and a registration token are required")
		fmt.Fprintln(os.Stderr, "usage: power-manage-agent enroll -server=URL -token-file=PATH")
		fmt.Fprintln(os.Stderr, "   or: PM_REGISTRATION_TOKEN=… power-manage-agent enroll -server=URL")
		fmt.Fprintln(os.Stderr, "   or: power-manage-agent enroll 'power-manage://server:port?token=xxx&pin=…'")
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

	// Enroll via the local socket. The SDK proto no longer carries
	// a TLS-bypass field; agents always validate the server cert
	// during enrollment. An optional CA fingerprint pin is verified
	// server-side before the returned CA is trusted.
	resp, err := client.Enroll(ctx, connect.NewRequest(&pm.EnrollRequest{
		ServerUrl:        *server,
		Token:            resolvedToken,
		CaFingerprintPin: strings.ReplaceAll(strings.TrimSpace(caPin), ":", ""),
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
		ServerUrl:        parsed.ServerURL,
		Token:            parsed.Token,
		CaFingerprintPin: strings.ReplaceAll(strings.TrimSpace(parsed.Pin), ":", ""),
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

type registrationURI struct {
	ServerURL string
	Token     string
	Pin       string // optional CA fingerprint pin
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
