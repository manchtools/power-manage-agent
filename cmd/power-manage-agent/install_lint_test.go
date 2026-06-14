package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readRepoFile reads a file at the agent repo root (two levels up from
// this package: agent/cmd/power-manage-agent → agent/).
func readRepoFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// WS7 #4: the power-manage:// URI handler must be OPT-IN (off by default),
// and the desktop entry must not auto-launch a terminal. An unconditional
// handler exposes the root-capable binary to drive-by links.
func TestInstall_DesktopHandlerOptIn(t *testing.T) {
	sh := readRepoFile(t, "install.sh")

	if !strings.Contains(sh, "--enable-uri-handler") {
		t.Error("install.sh must expose an --enable-uri-handler opt-in flag")
	}
	if !strings.Contains(sh, `if [[ "$ENABLE_URI_HANDLER" == "true" ]]`) {
		t.Error("install_desktop_handler must be gated behind ENABLE_URI_HANDLER (opt-in)")
	}
	// Default off: the env default must not be true.
	if strings.Contains(sh, `ENABLE_URI_HANDLER="${POWER_MANAGE_ENABLE_URI_HANDLER:-true}`) {
		t.Error("the URI handler must default to OFF")
	}
	// No auto-launching terminal entry.
	if strings.Contains(sh, "Terminal=true") {
		t.Error("the desktop entry must not set Terminal=true (drive-by auto-launch)")
	}
}

// WS7 #9: every capability in the systemd unit's CapabilityBoundingSet
// must carry a justification comment. Self-discovering: a cap added
// without a comment fails this test.
func TestInstall_CapsDocumented(t *testing.T) {
	sh := readRepoFile(t, "install.sh")

	var capLine string
	commentCaps := map[string]bool{}
	for _, l := range strings.Split(sh, "\n") {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "CapabilityBoundingSet=") {
			capLine = strings.TrimPrefix(trimmed, "CapabilityBoundingSet=")
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			for _, tok := range strings.Fields(trimmed) {
				tok = strings.Trim(tok, "/,.—-")
				if strings.HasPrefix(tok, "CAP_") {
					commentCaps[tok] = true
				}
			}
		}
	}

	if capLine == "" {
		t.Fatal("no CapabilityBoundingSet= line found in install.sh")
	}
	caps := strings.Fields(capLine)
	if len(caps) == 0 {
		t.Fatal("CapabilityBoundingSet is empty")
	}
	for _, c := range caps {
		if !commentCaps[c] {
			t.Errorf("capability %s in CapabilityBoundingSet has no justification comment", c)
		}
	}
}

// WS7 #10: the Containerfile must chmod the data dir 700, matching
// install.sh (it holds action secrets + the agent store).
func TestContainerfile_DataDirPerms(t *testing.T) {
	cf := readRepoFile(t, "Containerfile")
	if !strings.Contains(cf, "chmod 700 /var/lib/power-manage") {
		t.Error("Containerfile must `chmod 700 /var/lib/power-manage` after creating it")
	}
}
