package main

import "testing"

// WS15 #3 — the gateway-URL guard must reject every non-https://host value,
// consistently, using url.Parse discipline (scheme=="https" case-insensitively,
// empty Opaque, non-empty Host).
//
// runtime.go used strings.HasPrefix(addr, "http://"), which lets HTTP:// (case),
// Https:// (mixed case), https:foo (opaque), https: (no host), ftp://, h2c://,
// "" (empty), and " http://x" (leading whitespace) through to WithMTLSFromPEM.
// requireHTTPSGateway consolidates the cmd_selftest.go predicate so all gateway
// dial sites share one definition. "wrong" cases are sourced from the intent
// ("only a cleartext-refusing https network URL may reach WithMTLSFromPEM"),
// NOT from the old HasPrefix artifact.

func TestGatewayURLGuard_RejectsNonHTTPS(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		// correct
		{"https host with port", "https://gw.example:443", false},
		{"https host no port", "https://gw.example", false},
		{"https host with path", "https://gw.example/connect", false},

		// present-but-wrong
		{"lowercase http", "http://attacker", true},
		{"uppercase HTTP", "HTTP://attacker", true},
		{"mixed-case Https host", "Https://x", false}, // scheme is case-insensitive → valid https host
		{"mixed-case HTTP variant", "HtTp://x", true},
		{"opaque https", "https:foo", true},
		{"https no host", "https:", true},
		{"ftp scheme", "ftp://x", true},
		{"h2c scheme", "h2c://x", true},
		{"empty", "", true},
		{"leading whitespace http", " http://x", true},
		{"leading whitespace https", " https://x", false}, // trimmed → valid
		{"scheme-less host", "gw.example:443", true},
		{"bare host", "gw.example", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireHTTPSGateway(tc.addr)
			if tc.wantErr && err == nil {
				t.Fatalf("requireHTTPSGateway(%q) = nil, want error", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("requireHTTPSGateway(%q) = %v, want nil", tc.addr, err)
			}
		})
	}
}
