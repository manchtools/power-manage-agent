package store

import (
	"os"
	"strings"
	"testing"
)

// TestStore_NoBareErrNoRowsComparison is a self-discovering guard: store.go
// must compare sql.ErrNoRows via errors.Is, never ==, so a wrapped sentinel is
// handled. Guards against a vacuous pass on an empty/missing file.
func TestStore_NoBareErrNoRowsComparison(t *testing.T) {
	src, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatalf("read store.go: %v", err)
	}
	if len(src) == 0 {
		t.Fatal("store.go is empty — the guard would pass vacuously")
	}
	s := string(src)
	if strings.Contains(s, "== sql.ErrNoRows") || strings.Contains(s, "sql.ErrNoRows ==") {
		t.Error("store.go must use errors.Is(err, sql.ErrNoRows), not a == comparison (WS16 #12)")
	}
}
