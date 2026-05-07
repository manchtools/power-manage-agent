// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	sdk "github.com/manchtools/power-manage/sdk/go"
	pmcrypto "github.com/manchtools/power-manage/sdk/go/crypto"
)

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

	// Register via control server RPC. TLS verification is always
	// enforced — there is intentionally no opt-out, as bypassing it
	// during initial registration enables MITM attacks that can
	// substitute the gateway URL and a malicious certificate before
	// the agent has any trust anchor of its own.
	result, err := sdk.RegisterAgent(ctx, cfg.ServerURL, cfg.Token, hostname, version, csrPEM)
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

// startCertRotation runs a background loop that renews the agent's mTLS
// certificate before it expires. Renewal is attempted at 80% of the cert's
// lifetime. On failure it retries every hour.
//
// Consecutive failures are tracked so prolonged outages become visible
// in operator logs without an additional alerting pipeline. The first
// few failures stay at "the call failed once, retrying" volume; once
// the count crosses a threshold the messages escalate to mention how
// long the agent has been unable to rotate, which is what an operator
// needs to triage "is the control server reachable?".
func startCertRotation(ctx context.Context, credStore *credentials.Store, hostname string, logger *slog.Logger) {
	const (
		retryInterval     = 1 * time.Hour
		escalateThreshold = 3 // hours of consecutive failure before the log volume rises
	)
	consecutiveFailures := 0
	logRetryFailure := func(stage string, err error) {
		consecutiveFailures++
		attrs := []any{"stage", stage, "error", err, "consecutive_failures", consecutiveFailures}
		if consecutiveFailures >= escalateThreshold {
			// Escalated wording so a `journalctl -u power-manage-agent
			// | grep "rotation stalled"` query surfaces the issue
			// fast. The hours-stalled value is the operator-facing
			// triage handle.
			logger.Error("cert rotation: rotation stalled, control server may be unreachable",
				append(attrs, "hours_stalled", consecutiveFailures)...,
			)
		} else {
			logger.Error("cert rotation: renewal attempt failed, will retry", attrs...)
		}
	}

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
			logRetryFailure("generate_csr", err)
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
			logRetryFailure("configure_mtls", err)
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
			logRetryFailure("renew_certificate", err)
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
			logRetryFailure("save_credentials", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retryInterval):
			}
			continue
		}

		// Successful rotation — reset the consecutive-failure counter
		// so the next failure starts at 1, not stuck above the
		// escalation threshold from a prior outage.
		consecutiveFailures = 0
		logger.Info("cert rotation: certificate renewed successfully",
			"not_after", result.NotAfter,
		)
		// Loop to schedule next renewal based on the new cert
	}
}
