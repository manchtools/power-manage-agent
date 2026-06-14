// Package main is the entry point for the power-manage agent.
package main

import (
	"fmt"
	"net/url"
	"strings"
)

// requireHTTPSGateway validates that addr is a cleartext-refusing
// https://host network URL — the only kind permitted to reach the mTLS
// gateway dial (sdk.WithMTLSFromPEM). It is the single shared predicate for
// every gateway dial site (runtime.go, cmd_selftest.go) so the guard cannot
// drift between them.
//
// Parse the URL rather than checking a literal prefix so case variants
// (HTTP://, Https://), leading whitespace, opaque forms (https:foo), hostless
// forms (https:), and any non-https scheme (ftp://, h2c://, the empty scheme)
// all fail closed. The scheme is compared case-insensitively; the Opaque and
// Host checks catch the corner cases url.Parse leaves accepted: a bare
// "https:" parses with Scheme="https" but no Host, and an opaque "https:foo"
// parses with Opaque set rather than as a network URL — both would slip past a
// Scheme-only check.
func requireHTTPSGateway(addr string) error {
	trimmed := strings.TrimSpace(addr)
	parsed, err := url.Parse(trimmed)
	if err != nil || strings.ToLower(parsed.Scheme) != "https" || parsed.Opaque != "" || parsed.Host == "" {
		return fmt.Errorf("refusing non-https or hostless gateway URL %q: agent requires https://host for gateway connections", addr)
	}
	return nil
}
