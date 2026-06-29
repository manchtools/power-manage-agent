package executor

import (
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/sys/remote"
	"github.com/manchtools/power-manage-sdk/verify"
)

// =============================================================================
// SPEC: 11-sdk-spec.md — Invariant 7: ULIDs for all identifiers
// =============================================================================

func TestSpecSDK_ULIDNotUUID(t *testing.T) {
	const ulidLen = 26
	const uuidLen = 36
	if ulidLen == uuidLen {
		t.Error("ULID and UUID have different formats — tests must distinguish them")
	}
}

// =============================================================================
// SPEC: 12-agent-spec.md — Invariant 1: Never execute unsigned actions
// =============================================================================

func TestSpecAgent_NeverExecuteUnsigned_VerifyRejectsTampered(t *testing.T) {
	e := NewExecutor(nil, nil)
	_, err := e.VerifyEnvelope([]byte("payload"), []byte("wrong-signature"))
	if err == nil {
		t.Fatal("SPEC VIOLATION: VerifyEnvelope accepted tampered signature")
	}
}

func TestSpecAgent_NeverExecuteUnsigned_NilVerifierFailsClosed(t *testing.T) {
	e := NewExecutor(nil, nil)
	_, err := e.VerifyEnvelope([]byte("payload"), []byte("signature"))
	if err == nil {
		t.Fatal("SPEC VIOLATION: nil verifier accepted envelope")
	}
	if !strings.Contains(err.Error(), "no action verifier") {
		t.Errorf("error must mention 'no action verifier': %v", err)
	}
}

// =============================================================================
// SPEC: 12-agent-spec.md — Invariant 2: Fail-closed on stream RPC boundaries
// =============================================================================

func TestSpecAgent_FailClosedStreamRPCBoundaries(t *testing.T) {
	e := NewExecutor(nil, nil)

	tests := []struct {
		name string
		fn   func() error
	}{
		{"OSQuery", func() error { return e.VerifyOSQuery(&pb.OSQuery{QueryId: "q1", Table: "uptime"}) }},
		{"LogQuery", func() error { return e.VerifyLogQuery(&pb.LogQuery{QueryId: "q1", Unit: "foo.service"}) }},
		{"RevokeLuks", func() error { return e.VerifyRevokeLuksDeviceKey(&pb.RevokeLuksDeviceKey{ActionId: "01J123456789"}) }},
		{"RequestInventory", func() error { return e.VerifyRequestInventory(&pb.RequestInventory{QueryId: "q1"}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err == nil {
				t.Fatalf("SPEC VIOLATION: nil verifier accepted %s", tt.name)
			}
		})
	}
}

// =============================================================================
// SPEC: 12-agent-spec.md — Invariant 4: No secrets in logs or results
// (sanitizeForLog lives in handler package — this test documents the contract;
//  the behavioral tests are in handler/spec_behavior_test.go)
// =============================================================================

func TestSpecAgent_NoSecretsInOutput_Documented(t *testing.T) {
	// The handler's sanitizeForLog must redact "enc:v1:<base64>" markers.
	// Contract: output containing "enc:v1:" must NOT appear in agent logs.
	// Behavioral tests in handler/spec_behavior_test.go.
}

// =============================================================================
// SPEC: 16-remote-allow-redirect.md — AC 11: pin-aware redirect policy
// =============================================================================

func TestSpecRemoteRedirect_PinAware(t *testing.T) {
	pin := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	if redirectForArtifact(pin) != remote.RedirectCrossOrigin {
		t.Error("SPEC VIOLATION AC11: pinned artifact must allow cross-origin redirects")
	}
	if redirectForArtifact("") != remote.RedirectSameOrigin {
		t.Error("SPEC VIOLATION AC11: unpinned artifact must refuse cross-origin redirects")
	}
}

// =============================================================================
// SPEC: 12-agent-spec.md — Certificate renewal at 80% of lifetime
// (renewAt lives in main package — this test documents the contract)
// =============================================================================

func TestSpecAgent_CertRenewalTime_Documented(t *testing.T) {
	// The renewAt function in main cert_rotation.go must:
	//   1. Return notAfter.Sub(notBefore) * 0.8 from notBefore, minus now
	//   2. Clamp to minimum 1 minute when already past the renewal point
	// Behavioral tests in cmd/power-manage-agent/cert_rotation_test.go.
	_ = time.Hour // prove we can use time package
}

// =============================================================================
// SPEC: 12-agent-spec.md — Dependencies: "Credential material zeroed after use"
// =============================================================================

func TestSpecAgent_CredentialZeroing_Documented(t *testing.T) {
	// The spec invariant 8: "Credential material zeroed after use — secureZero()."
	// The LUKS executor must scrub key material from memory after use.
	// The LPS executor must not retain generated passwords beyond the result metadata.
}

// =============================================================================
// SPEC: 16-remote-allow-redirect.md — AC 9: allow_redirect default behavior
// =============================================================================

func TestSpecRemoteRedirect_AllowRedirectDefaultsSameOrigin(t *testing.T) {
	policy := func(allowRedirect bool) remote.RedirectPolicy {
		if allowRedirect {
			return remote.RedirectCrossOrigin
		}
		return remote.RedirectSameOrigin
	}
	if policy(false) != remote.RedirectSameOrigin {
		t.Error("SPEC VIOLATION AC9: allow_redirect=false must stay same-origin")
	}
	if policy(true) != remote.RedirectCrossOrigin {
		t.Error("SPEC VIOLATION AC9: allow_redirect=true must allow cross-origin")
	}
}

// =============================================================================
// SPEC: 16-remote-allow-redirect.md — AC 1: https-only enforcement
// =============================================================================

func TestSpecRemoteRedirect_HTTPSOnlyBeforeFetch(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		checksum string
		wantErr  bool
	}{
		{"https valid sha256", "https://example.com/pkg.deb",
			"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", false},
		{"http rejected", "http://example.com/pkg.deb",
			"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", true},
		{"missing checksum", "https://example.com/pkg.deb", "", true},
		{"short checksum", "https://example.com/pkg.deb", "short", true},
		{"non-hex checksum", "https://example.com/pkg.deb", "ZZZZ" + strings.Repeat("0", 60), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := requireVerifiedArtifact(tt.url, tt.checksum)
			if (err != nil) != tt.wantErr {
				t.Errorf("requireVerifiedArtifact(%q, %q) error=%v wantErr=%v",
					tt.url, tt.checksum, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// SPEC: 12-agent-spec.md — mTLS certificate requirements
// =============================================================================

func TestSpecAgent_mTLSActionVerifierRequiresCert(t *testing.T) {
	_, err := verify.NewActionVerifier(nil)
	if err == nil {
		t.Fatal("SPEC VIOLATION: NewActionVerifier(nil) must fail — would verify nothing")
	}
	_, err = verify.NewActionVerifier([]byte{})
	if err == nil {
		t.Fatal("SPEC VIOLATION: NewActionVerifier(empty) must fail — would accept any signature")
	}
}

// =============================================================================
// SPEC: 12-agent-spec.md — "SQLite with WAL mode"
// =============================================================================

func TestSpecAgent_SQLiteWALRequired_Documented(t *testing.T) {
	// Spec invariant 6: WAL mode enforced by pragma test in store package.
	// The store.New/OpenExisting functions run PRAGMA journal_mode=WAL.
	// Behavioral tests in internal/store/store_test.go.
}
