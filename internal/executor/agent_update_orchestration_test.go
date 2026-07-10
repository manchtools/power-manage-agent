package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// agentScript builds a staged "agent binary" as a shell script that
// answers `version`, `self-test`, and `install-unit` (recording the
// invocation argv to "$0.install-unit", spec 27), so executeAgentUpdate
// can be driven end-to-end without a real binary.
func agentScript(version string, selfTestExit int) []byte {
	return agentScriptUnitExit(version, selfTestExit, 0)
}

// agentScriptUnitExit is agentScript with a controllable install-unit
// exit code, for the fail-open test.
func agentScriptUnitExit(version string, selfTestExit, installUnitExit int) []byte {
	return []byte(fmt.Sprintf(`#!/bin/sh
case "$1" in
  version) echo %q ;;
  self-test) exit %d ;;
  install-unit) shift; echo "$@" > "$0.install-unit"; exit %d ;;
  *) exit 0 ;;
esac
`, version, selfTestExit, installUnitExit))
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// updateHarness wires an executor with an AgentUpdateConfig pointed at a
// tmp "installed" binary, an httptest TLS server serving the staged
// binary + a SHA256SUMS document, and a Shutdown spy.
type updateHarness struct {
	e            *Executor
	binaryPath   string
	oldBytes     []byte
	srv          *httptest.Server
	shutdownCh   chan struct{}
	shutdownOnce sync.Once
}

// newUpdateHarness serves `serveBody` at /agent and `sumsBody` at /sums.
func newUpdateHarness(t *testing.T, runningVersion string, serveBody, sumsBody []byte) *updateHarness {
	t.Helper()
	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "power-manage-agent")
	oldBytes := []byte("#!/bin/sh\necho OLD\n")
	if err := os.WriteFile(binaryPath, oldBytes, 0o755); err != nil {
		t.Fatalf("seed binary: %v", err)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent":
			w.Write(serveBody)
		case "/sums":
			w.Write(sumsBody)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	h := &updateHarness{binaryPath: binaryPath, oldBytes: oldBytes, srv: srv, shutdownCh: make(chan struct{})}
	e := &Executor{logger: slog.Default(), now: time.Now}
	e.httpClient = srv.Client() // e.httpClient still covers the agent's other fetches (GPG keys, repo metadata)
	// Both the binary download (fetchArtifact -> remote.Fetch) and the checksum_url
	// download (remote.FetchBytes) route through the package remoteHTTPClient seam;
	// point it at the test TLS server.
	prevRemoteClient := remoteHTTPClient
	remoteHTTPClient = srv.Client()
	t.Cleanup(func() { remoteHTTPClient = prevRemoteClient })
	e.SetUpdateConfig(&AgentUpdateConfig{
		Version:    runningVersion,
		DataDir:    t.TempDir(),
		BinaryPath: binaryPath,
		Shutdown:   func() { h.shutdownOnce.Do(func() { close(h.shutdownCh) }) },
	})
	h.e = e
	return h
}

func (h *updateHarness) params(expectedSha string) *pb.AgentUpdateParams {
	return &pb.AgentUpdateParams{
		Amd64: &pb.AgentUpdateArch{
			BinaryUrl:      h.srv.URL + "/agent",
			ChecksumUrl:    h.srv.URL + "/sums",
			ExpectedSha256: expectedSha,
		},
		Arm64: &pb.AgentUpdateArch{
			BinaryUrl:      h.srv.URL + "/agent",
			ChecksumUrl:    h.srv.URL + "/sums",
			ExpectedSha256: expectedSha,
		},
	}
}

func (h *updateHarness) shutdownCalled() bool {
	select {
	case <-h.shutdownCh:
		return true
	case <-time.After(4 * time.Second):
		// NOT tightened (#174 proposed 500ms): the update path sleeps
		// deliberately before shutdown, so a short timeout false-fails.
		return false
	}
}

func (h *updateHarness) currentBinary(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(h.binaryPath)
	if err != nil {
		t.Fatalf("read binary: %v", err)
	}
	return b
}

// WS7 #6: a binary whose bytes do not hash to the action's
// expected_sha256 is rejected; the swap is aborted, the live binary is
// byte-identical, no .bak is created, Shutdown is not called.
func TestExecuteAgentUpdate_ChecksumMismatchAbortsSwap(t *testing.T) {
	genuine := agentScript("v2026.06.05", 0)
	tampered := append([]byte{}, genuine...)
	tampered[len(tampered)-2] ^= 0xff // flip a non-terminal byte

	// expected_sha256 is the hash of the GENUINE bytes; the server serves
	// TAMPERED bytes → mismatch (intent: hash binds content).
	h := newUpdateHarness(t, "v2026.06.01", tampered, nil)
	_, changed, err := h.e.executeAgentUpdate(context.Background(), h.params(sha256hex(genuine)))

	if err == nil {
		t.Fatal("checksum mismatch must abort the update")
	}
	if changed {
		t.Error("changed must be false on checksum mismatch")
	}
	if got := h.currentBinary(t); string(got) != string(h.oldBytes) {
		t.Error("live binary must be unchanged on checksum mismatch")
	}
	if _, statErr := os.Stat(h.binaryPath + ".bak"); statErr == nil {
		t.Error(".bak must not be created when the swap aborts")
	}
}

// WS7 #1 (core): when expected_sha256 is present, the swap is gated on it
// and a malicious same-origin checksum document is NOT trusted. Serve a
// SHA256SUMS that advertises a MATCHING hash for the tampered bytes while
// expected_sha256 holds the genuine hash → tampered binary rejected.
func TestExecuteAgentUpdate_HashBoundToSignedAction_NotChecksumFile(t *testing.T) {
	genuine := agentScript("v2026.06.05", 0)
	tampered := append([]byte{}, genuine...)
	tampered[len(tampered)-2] ^= 0xff

	// The lying checksum file vouches for the tampered bytes.
	sums := []byte(sha256hex(tampered) + "  agent\n")
	h := newUpdateHarness(t, "v2026.06.01", tampered, sums)

	_, changed, err := h.e.executeAgentUpdate(context.Background(), h.params(sha256hex(genuine)))
	if err == nil {
		t.Fatal("tampered binary must be rejected even when a same-origin checksum file vouches for it")
	}
	if changed {
		t.Error("changed must be false")
	}
	if got := h.currentBinary(t); string(got) != string(h.oldBytes) {
		t.Error("live binary must be unchanged")
	}
}

// WS7 #6: a staged binary whose self-test fails keeps the current binary.
func TestExecuteAgentUpdate_SelfTestFailKeepsBinary(t *testing.T) {
	staged := agentScript("v2026.06.05", 1) // self-test exits non-zero
	h := newUpdateHarness(t, "v2026.06.01", staged, nil)

	_, changed, err := h.e.executeAgentUpdate(context.Background(), h.params(sha256hex(staged)))
	if err == nil {
		t.Fatal("self-test failure must abort the update")
	}
	if changed {
		t.Error("changed must be false on self-test failure")
	}
	if got := h.currentBinary(t); string(got) != string(h.oldBytes) {
		t.Error("live binary must be unchanged on self-test failure")
	}
}

// WS7 #6 happy path: correct sha + passing self-test + newer version →
// binary swapped, .bak holds old bytes, Shutdown invoked.
func TestExecuteAgentUpdate_HappyPathSwapsAndShutsDown(t *testing.T) {
	staged := agentScript("v2026.06.05", 0)
	h := newUpdateHarness(t, "v2026.06.01", staged, nil)

	_, changed, err := h.e.executeAgentUpdate(context.Background(), h.params(sha256hex(staged)))
	if err != nil {
		t.Fatalf("happy-path update failed: %v", err)
	}
	if !changed {
		t.Error("changed must be true on a successful update")
	}
	if got := h.currentBinary(t); string(got) != string(staged) {
		t.Error("live binary must be the staged bytes after swap")
	}
	bak, err := os.ReadFile(h.binaryPath + ".bak")
	if err != nil {
		t.Fatalf("read .bak: %v", err)
	}
	if string(bak) != string(h.oldBytes) {
		t.Error(".bak must hold the previous binary")
	}
	if !h.shutdownCalled() {
		t.Error("Shutdown must be invoked after a successful update")
	}
}

// TestExecuteAgentUpdate_RefreshesUnitFromNewBinary pins spec 27 AC 4:
// after the swap + self-test and BEFORE the shutdown signal, the
// updater invokes the NEW binary's install-unit with the running data
// dir — so the respawn systemd performs starts the new binary under
// the new unit.
func TestExecuteAgentUpdate_RefreshesUnitFromNewBinary(t *testing.T) {
	staged := agentScript("v2026.06.05", 0)
	h := newUpdateHarness(t, "v2026.06.01", staged, nil)

	_, changed, err := h.e.executeAgentUpdate(context.Background(), h.params(sha256hex(staged)))
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	if !changed {
		t.Error("changed must be true")
	}
	argv, err := os.ReadFile(h.binaryPath + ".install-unit")
	if err != nil {
		t.Fatalf("install-unit was not invoked on the new binary: %v", err)
	}
	if !strings.Contains(string(argv), "--data-dir="+h.e.updateCfg.DataDir) {
		t.Errorf("install-unit argv = %q, want --data-dir=%s", string(argv), h.e.updateCfg.DataDir)
	}
	if !h.shutdownCalled() {
		t.Error("Shutdown must still be invoked after the unit refresh")
	}
}

// TestExecuteAgentUpdate_UnitInstallFailureIsFailOpen pins the second
// half of AC 4: a failing install-unit never aborts a completed binary
// swap — the update still succeeds and the shutdown fires (the new
// binary's startup reconcile retries after the respawn).
func TestExecuteAgentUpdate_UnitInstallFailureIsFailOpen(t *testing.T) {
	staged := agentScriptUnitExit("v2026.06.05", 0, 1)
	h := newUpdateHarness(t, "v2026.06.01", staged, nil)

	_, changed, err := h.e.executeAgentUpdate(context.Background(), h.params(sha256hex(staged)))
	if err != nil {
		t.Fatalf("update must succeed despite install-unit failure: %v", err)
	}
	if !changed {
		t.Error("changed must be true")
	}
	if !h.shutdownCalled() {
		t.Error("Shutdown must be invoked despite install-unit failure")
	}
}

// WS7 (revised): an action with NEITHER expected_sha256 NOR checksum_url
// has no integrity source and is refused fail-closed (also enforced
// server-side). The agent-update path uses downloadToFile, which has no
// checksum chokepoint of its own.
func TestExecuteAgentUpdate_RefusesNoIntegritySource(t *testing.T) {
	staged := agentScript("v2026.06.05", 0)
	h := newUpdateHarness(t, "v2026.06.01", staged, nil)

	// No expected_sha256 AND no checksum_url.
	noIntegrity := &pb.AgentUpdateParams{
		Amd64: &pb.AgentUpdateArch{BinaryUrl: h.srv.URL + "/agent"},
		Arm64: &pb.AgentUpdateArch{BinaryUrl: h.srv.URL + "/agent"},
	}
	_, changed, err := h.e.executeAgentUpdate(context.Background(), noIntegrity)
	if err == nil {
		t.Fatal("an action with no integrity source must be refused")
	}
	if changed {
		t.Error("changed must be false")
	}
	if got := h.currentBinary(t); string(got) != string(h.oldBytes) {
		t.Error("live binary must be unchanged")
	}
}

// WS7 (revised): the DEFAULT path — no pinned expected_sha256, integrity
// verified against the operator's checksum_url (SHA256SUMS). This is what
// lets binary_url/checksum_url track "latest" hands-off. A correct
// checksum file + newer version → swap + shutdown.
func TestExecuteAgentUpdate_ChecksumURLFallback(t *testing.T) {
	staged := agentScript("v2026.06.05", 0)
	// SHA256SUMS line for the binary served at /agent (filename "agent").
	sums := []byte(sha256hex(staged) + "  agent\n")
	h := newUpdateHarness(t, "v2026.06.01", staged, sums)

	// No expected_sha256 → agent fetches + verifies via checksum_url.
	p := &pb.AgentUpdateParams{
		Amd64: &pb.AgentUpdateArch{BinaryUrl: h.srv.URL + "/agent", ChecksumUrl: h.srv.URL + "/sums"},
		Arm64: &pb.AgentUpdateArch{BinaryUrl: h.srv.URL + "/agent", ChecksumUrl: h.srv.URL + "/sums"},
	}
	_, changed, err := h.e.executeAgentUpdate(context.Background(), p)
	if err != nil {
		t.Fatalf("checksum_url fallback update failed: %v", err)
	}
	if !changed {
		t.Error("changed must be true on a successful checksum_url-verified update")
	}
	if got := h.currentBinary(t); string(got) != string(staged) {
		t.Error("binary must be swapped to the staged bytes")
	}
	bak, err := os.ReadFile(h.binaryPath + ".bak")
	if err != nil {
		t.Fatalf("read .bak: %v", err)
	}
	if string(bak) != string(h.oldBytes) {
		t.Error(".bak must hold the previous binary")
	}
	if !h.shutdownCalled() {
		t.Error("Shutdown must be invoked after a successful update")
	}
}

// A checksum_url whose SHA256SUMS does NOT match the downloaded binary is
// rejected (no swap).
func TestExecuteAgentUpdate_ChecksumURLMismatchRejected(t *testing.T) {
	staged := agentScript("v2026.06.05", 0)
	tampered := append([]byte{}, staged...)
	tampered[len(tampered)-2] ^= 0xff
	// SHA256SUMS vouches for the GENUINE bytes; the server serves TAMPERED.
	sums := []byte(sha256hex(staged) + "  agent\n")
	h := newUpdateHarness(t, "v2026.06.01", tampered, sums)

	p := &pb.AgentUpdateParams{
		Amd64: &pb.AgentUpdateArch{BinaryUrl: h.srv.URL + "/agent", ChecksumUrl: h.srv.URL + "/sums"},
		Arm64: &pb.AgentUpdateArch{BinaryUrl: h.srv.URL + "/agent", ChecksumUrl: h.srv.URL + "/sums"},
	}
	_, changed, err := h.e.executeAgentUpdate(context.Background(), p)
	if err == nil {
		t.Fatal("a checksum_url mismatch must abort the update")
	}
	if changed {
		t.Error("changed must be false")
	}
	if got := h.currentBinary(t); string(got) != string(h.oldBytes) {
		t.Error("live binary must be unchanged")
	}
}

// WS7 #2: an http binary_url is rejected at validateHTTPS before any
// download (fail-closed ordering).
func TestExecuteAgentUpdate_HTTPSourceRejected(t *testing.T) {
	staged := agentScript("v2026.06.05", 0)
	h := newUpdateHarness(t, "v2026.06.01", staged, nil)
	p := h.params(sha256hex(staged))
	p.Amd64.BinaryUrl = "http://example.com/agent"
	p.Arm64.BinaryUrl = "http://example.com/agent"

	_, changed, err := h.e.executeAgentUpdate(context.Background(), p)
	if err == nil {
		t.Fatal("http binary_url must be rejected")
	}
	if changed {
		t.Error("changed must be false")
	}
	if got := h.currentBinary(t); string(got) != string(h.oldBytes) {
		t.Error("live binary must be unchanged")
	}
}
