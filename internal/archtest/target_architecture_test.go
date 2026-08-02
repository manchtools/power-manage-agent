package archtest

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetArchitectureHasNoAbolishedAgentRuntime(t *testing.T) {
	root := moduleRoot(t)
	forbidden := []string{
		"github.com/manchtools/power-manage-sdk/gen/go/pm/v1",
		"github.com/manchtools/power-manage-sdk/verify",
		"SignedActionEnvelope",
		"ActionEnvelope",
		"SyncActions",
		"SyncStandaloneAndGrouped",
		"SaveAction(",
		"GetDueActions(",
		"GetDueGroups(",
	}
	required := map[string]bool{
		"ManifestDelivery":  false,
		"MarkRebootStarted": false,
		"SealedValue":       false,
	}
	files := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files++
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		for _, needle := range forbidden {
			if strings.Contains(text, needle) {
				t.Errorf("%s contains abolished agent architecture marker %q", path, needle)
			}
		}
		if strings.Contains(strings.ToLower(text), "gateway") {
			t.Errorf("%s reintroduces Gateway vocabulary into production agent code", path)
		}
		for marker := range required {
			if strings.Contains(text, marker) {
				required[marker] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("matches-zero guard: no production Go files were inspected")
	}
	for marker, found := range required {
		if !found {
			t.Errorf("matches-zero guard: required target marker %q was not found", marker)
		}
	}
	module, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dependency := range []string{"asynq", "redis", "valkey", "power-manage-sdk/verify"} {
		if strings.Contains(strings.ToLower(string(module)), dependency) {
			t.Errorf("go.mod contains abolished runtime dependency %q", dependency)
		}
	}
}

func TestAgentUsesOneFreshManifestSchema(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(moduleRoot(t), "internal", "store", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	var migrations []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".sql") {
			migrations = append(migrations, entry.Name())
		}
	}
	// The agent's schema is rooted in ONE fresh, manifest-native baseline.
	// os.ReadDir sorts by name, so requiring that baseline FIRST rejects a
	// second baseline, a renamed one, and anything numbered ahead of it.
	//
	// The assertion is about the baseline, not a file count. The tracked
	// baseline is immutable, so schema for new behavior (002 one-shot
	// terminality) is an ordinary numbered forward migration. Abolished
	// architecture is caught by the forbidden-marker sweep above.
	if len(migrations) == 0 || migrations[0] != "001_initial_schema.sql" {
		t.Fatalf("agent schema must start from the fresh manifest-native baseline, got %v", migrations)
	}
}
