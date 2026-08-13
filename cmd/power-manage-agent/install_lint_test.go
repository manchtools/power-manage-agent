package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// WS9 #3: the install flow must NOT pass the registration token on argv
// (visible via /proc/<pid>/cmdline). It must deliver it via -token-file,
// created mode 0600.
func TestInstall_TokenDeliveredViaFileNotArgv(t *testing.T) {
	sh := readRepoFile(t, "install.sh")

	if strings.Contains(sh, "-token=$REGISTRATION_TOKEN") {
		t.Error("install.sh must not pass the registration token on argv; use -token-file")
	}
	if !strings.Contains(sh, "-token-file=") {
		t.Error("install.sh enrollment must deliver the token via -token-file")
	}
	if !strings.Contains(sh, `chmod 600 "$token_file"`) {
		t.Error("the install.sh token file must be created mode 0600")
	}
}

func TestInstall_EnrollmentRequiresCAPin(t *testing.T) {
	sh := readRepoFile(t, "install.sh")
	for _, required := range []string{"--pin", "CA_FINGERPRINT_PIN", `-pin=$CA_FINGERPRINT_PIN`} {
		if !strings.Contains(sh, required) {
			t.Errorf("install.sh enrollment is missing %q", required)
		}
	}
}

func TestInstall_VerifiesPublisherSignatureBeforeChecksum(t *testing.T) {
	sh := readRepoFile(t, "install.sh")
	for _, required := range []string{
		"SHA256SUMS.sig", "__RELEASE_SIGNING_PUBLIC_KEY__", "openssl pkeyutl -verify", "verify_release_manifest",
	} {
		if !strings.Contains(sh, required) {
			t.Errorf("install.sh is missing signed-release requirement %q", required)
		}
	}
	signatureCheck := strings.Index(sh, `if ! verify_release_manifest "$tmp_sums" "$tmp_signature" "$tmp_public"; then`)
	hashCheck := strings.Index(sh, `actual_sha=$(sha256sum "$tmp_binary"`)
	if signatureCheck < 0 || hashCheck < 0 || signatureCheck > hashCheck {
		t.Error("publisher signature must be verified before trusting SHA256SUMS")
	}
	if strings.Contains(sh, "POWER_MANAGE_RELEASE_SIGNING_PUBLIC_KEY") {
		t.Error("the published installer's pinned release key must not be replaceable through the environment")
	}
}

func TestReleaseWorkflowSignsChecksumsInProtectedEnvironment(t *testing.T) {
	workflow := readRepoFile(t, filepath.Join(".github", "workflows", "release.yml"))
	_, releaseJob, ok := strings.Cut(workflow, "\n  release:\n")
	if !ok {
		t.Fatal("release workflow is missing the release job")
	}
	for _, required := range []string{
		"environment: releases", "RELEASE_SIGNING_PRIVATE_KEY", "RELEASE_SIGNING_PUBLIC_KEY",
		"SHA256SUMS.sig", "openssl pkeyutl -sign -rawin", "ED25519 Private-Key:",
	} {
		if !strings.Contains(releaseJob, required) {
			t.Errorf("release workflow is missing %q", required)
		}
	}
}

func TestReleaseWorkflowPrereleaseInstructionsUseExactTag(t *testing.T) {
	workflow := readRepoFile(t, filepath.Join(".github", "workflows", "release.yml"))
	_, prerelease, ok := strings.Cut(workflow, `if [[ "${{ needs.build.outputs.is_prerelease }}" == "true" ]]; then`)
	if !ok {
		t.Fatal("release workflow is missing the prerelease release-body branch")
	}
	prerelease, _, ok = strings.Cut(prerelease, "          else")
	if !ok {
		t.Fatal("release workflow is missing the stable release-body branch")
	}
	if strings.Contains(prerelease, "releases/latest/download/install.sh") {
		t.Error("prerelease instructions must not bootstrap the latest stable installer")
	}
	if !strings.Contains(prerelease, `releases/download/${TAG}/install.sh`) {
		t.Error("prerelease instructions must use the installer from the exact release tag")
	}

	// Issue #204: both prerelease installer URLs must be built from
	// ${{ github.repository }}. Hardcoding the upstream slug makes a fork's
	// generated release body send its users to upstream's assets — which are
	// signed with upstream's key and contain none of the fork's builds,
	// contradicting the BYOK downstream signing contract in README.md.
	installers := releaseDownloadRepositories(prerelease)
	if len(installers) < 2 {
		t.Fatalf("matches-zero guard: the prerelease body documents an install and an update installer, so it must carry at least 2 release-download URLs; found %d", len(installers))
	}
	for _, repo := range installers {
		if repo != githubRepositoryExpression {
			t.Errorf("prerelease installer URL hardcodes repository %q; use %s so a fork's release body points at the fork's own signed assets", repo, githubRepositoryExpression)
		}
	}
}

// githubRepositoryExpression is the Actions expression that renders to the
// owner/repo slug of whatever repository is running the workflow.
const githubRepositoryExpression = "${{ github.repository }}"

// releaseDownloadRepositoryPattern captures the owner/repo slug of every
// github.com release URL — both `releases/download/<tag>/` and
// `releases/latest/download/`. The capture is non-greedy so it stops at the
// first `/releases/`, and `.` (not `\S`) because the correct value,
// ${{ github.repository }}, contains spaces.
var releaseDownloadRepositoryPattern = regexp.MustCompile(`https://github\.com/(.+?)/releases/(?:latest/)?download/`)

// releaseDownloadRepositories returns the repository slug used by every
// github.com release-download URL in the given workflow fragment.
func releaseDownloadRepositories(fragment string) []string {
	var out []string
	for _, m := range releaseDownloadRepositoryPattern.FindAllStringSubmatch(fragment, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestReleaseWorkflowBodyURLsAreForkSafe generalises the rule the prerelease
// test applies to its own branch: NO release URL anywhere in the generated
// release body may name a repository literally. The stable branch documents
// four more installer commands than the prerelease branch, and a hardcoded
// slug is the same defect there — a fork tagging a stable release would
// publish instructions that install upstream's signed binaries.
//
// Self-discovering: it reads whatever URLs the step emits, so a newly added
// installer snippet is covered without editing a list here.
func TestReleaseWorkflowBodyURLsAreForkSafe(t *testing.T) {
	workflow := readRepoFile(t, filepath.Join(".github", "workflows", "release.yml"))
	_, body, ok := strings.Cut(workflow, "\n      - name: Generate release body\n")
	if !ok {
		t.Fatal("release workflow is missing the release-body step")
	}
	body, _, ok = strings.Cut(body, "\n      - name: ")
	if !ok {
		t.Fatal("release workflow's release-body step is not followed by another step")
	}

	repos := releaseDownloadRepositories(body)
	if len(repos) == 0 {
		t.Fatal("matches-zero guard: extracted no github.com release-download URLs from the release-body step; the pattern is broken")
	}
	for _, repo := range repos {
		if repo != githubRepositoryExpression {
			t.Errorf("release body URL hardcodes repository %q; use %s so forks publish instructions for their own release assets", repo, githubRepositoryExpression)
		}
	}
}

func TestInstall_ReleaseVerifierAcceptsOnlyConfiguredSigner(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is required by the production installer")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("abc  power-manage-agent-linux-amd64\n")
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "SHA256SUMS")
	signaturePath := filepath.Join(directory, "SHA256SUMS.sig")
	publicPath := filepath.Join(directory, "release-public.der")
	for path, body := range map[string][]byte{
		manifestPath: manifest, signaturePath: ed25519.Sign(privateKey, manifest), publicPath: publicDER,
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	installer := filepath.Join("..", "..", "install.sh")
	if output, err := exec.Command("bash", installer, "--internal-verify-release-manifest", manifestPath, signaturePath, publicPath).CombinedOutput(); err != nil {
		t.Fatalf("valid publisher signature rejected: %v\n%s", err, output)
	}
	if err := os.WriteFile(manifestPath, append(manifest, 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("bash", installer, "--internal-verify-release-manifest", manifestPath, signaturePath, publicPath).Run(); err == nil {
		t.Fatal("installer accepted a manifest modified after signing")
	}
}

// WS7 #9: every capability in the systemd unit's CapabilityBoundingSet
// must carry a justification comment. Self-discovering: a cap added
// without a comment fails this test.
// TestInstall_CapsDocumented walks the agent's embedded unit TEMPLATE
// (the single source since spec 27 — install.sh no longer carries the
// unit) and requires a justification comment for every capability in
// the bounding set.
func TestInstall_CapsDocumented(t *testing.T) {
	sh := readRepoFile(t, filepath.Join("internal", "unit", "power-manage-agent.service.tmpl"))

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
		t.Fatal("no CapabilityBoundingSet= line found in the unit template")
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

// TestInstall_SingleUnitSource is spec 27's grep guard: install.sh must
// carry NO copy of the unit (no heredoc, no unit directives) — the
// embedded template is the single source — and must invoke the
// binary's install-unit instead. The invocation assertion is the
// matches-zero guard: if the subcommand is ever renamed, this fails
// loudly rather than the directive checks passing vacuously against a
// script that installs no unit at all.
func TestInstall_SingleUnitSource(t *testing.T) {
	sh := readRepoFile(t, "install.sh")

	for _, directive := range []string{"CapabilityBoundingSet=", "AmbientCapabilities=", "ExecStart=", "RestrictRealtime=", "[Service]"} {
		if strings.Contains(sh, directive) {
			t.Errorf("install.sh contains unit directive %q — the unit's single source is the embedded template", directive)
		}
	}
	if !strings.Contains(sh, `"$BINARY_PATH" install-unit --data-dir="$DATA_DIR"`) {
		t.Error("install.sh must install the unit via the binary's install-unit subcommand")
	}
	if strings.Contains(sh, "systemctl --version") {
		t.Error("the systemd-version probe moved into the binary; install.sh must not probe")
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

// The release build substitutes the public key into install.sh with a GLOBAL
// sed over the placeholder. rc1 shipped an installer whose "not configured"
// guard was itself the placeholder literal, so the sed rewrote the guard into
// comparing the configured key against itself and every SIGNED release
// refused to install. The full placeholder may therefore appear exactly once
// — the assignment the sed is meant to hit — and the guard must assemble its
// sentinel at run time where no substitution can reach it.
func TestInstall_PlaceholderAppearsOnlyInTheAssignment(t *testing.T) {
	sh := readRepoFile(t, "install.sh")
	const placeholder = "__RELEASE_SIGNING_PUBLIC_KEY__"

	count := strings.Count(sh, placeholder)
	if count == 0 {
		t.Fatal("install.sh must carry the release-key placeholder assignment; a build with none has nothing to substitute")
	}
	if count != 1 {
		t.Errorf("the release-key placeholder appears %d times; the release sed replaces every occurrence, so only the assignment may carry it", count)
	}
	if !strings.Contains(sh, `RELEASE_SIGNING_PUBLIC_KEY="`+placeholder+`"`) {
		t.Error("the single placeholder occurrence must be the assignment the release sed substitutes")
	}

	// Simulate the release substitution and prove the guard survives it: the
	// substituted script must never compare the variable against the value
	// that was just injected.
	substituted := strings.ReplaceAll(sh, placeholder, "TESTKEYBASE64")
	if strings.Contains(substituted, `== "TESTKEYBASE64"`) {
		t.Error("after key substitution the configured-key guard compares the key against itself; assemble the sentinel at run time")
	}
}

// Self-discovering generalization of the placeholder rule: every release
// placeholder declared in install.sh must (a) appear exactly once, on the
// assignment its sed targets, (b) actually be substituted by the release
// workflow, and (c) survive a simulated global substitution without any
// guard comparing a variable against the freshly injected value. A new
// placeholder added without workflow wiring, or referenced literally in a
// second place, fails here instead of in the next broken release.
func TestInstall_EveryPlaceholderStampedExactlyOnce(t *testing.T) {
	sh := readRepoFile(t, "install.sh")
	wf := readRepoFile(t, filepath.Join(".github", "workflows", "release.yml"))

	pattern := regexp.MustCompile(`__[A-Z][A-Z0-9_]*__`)
	counts := map[string]int{}
	for _, token := range pattern.FindAllString(sh, -1) {
		counts[token]++
	}
	if len(counts) == 0 {
		t.Fatal("install.sh declares no release placeholders; the release build would stamp nothing")
	}

	substituted := sh
	for token, count := range counts {
		if count != 1 {
			t.Errorf("placeholder %s appears %d times; the global release sed replaces every occurrence, so only its assignment may carry it", token, count)
		}
		if !strings.Contains(sh, `="`+token+`"`) {
			t.Errorf("placeholder %s must appear as a quoted assignment for the release sed to stamp", token)
		}
		if !strings.Contains(wf, token) {
			t.Errorf("release.yml never substitutes %s; a release would ship the raw placeholder and fail closed", token)
		}
		substituted = strings.ReplaceAll(substituted, token, "STAMPED_VALUE")
	}
	if strings.Contains(substituted, `== "STAMPED_VALUE"`) {
		t.Error("after substitution a guard compares a variable against the injected value; assemble sentinels at run time")
	}
}
