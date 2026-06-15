package store

import (
	"os"
	"strings"
	"testing"
)

// WS16 #12: GetGroupByID compared err == sql.ErrNoRows, which a wrapped
// sentinel would slip past. It now uses errors.Is. A missing group must still
// resolve to (nil, nil).
func TestGetGroupByID_MissingReturnsNilNil(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New store: %v", err)
	}
	defer st.Close()

	g, err := st.GetGroupByID("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err != nil {
		t.Fatalf("a missing group must not error, got: %v", err)
	}
	if g != nil {
		t.Fatalf("a missing group must return nil, got: %+v", g)
	}
}

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
