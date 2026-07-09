package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// transientSkipMarkers are the ONLY "skipped: …" success returns allowed to
// stay: skips that re-run on the next reconciliation (nothing structural
// about the device). Everything else claiming "skipped:" while returning
// success is the silent-skip bug class spec 23 AC 3 eliminates — structural
// inapplicability must return notApplicable(...) so it surfaces as
// EXECUTION_STATUS_NOT_APPLICABLE instead of a green SUCCESS.
var transientSkipMarkers = []string{
	"no signed-in desktop users",
}

// TestNoSilentSkipSuccessReturns is the self-discovering grep guard (spec 23
// AC 3): it sweeps every non-test source file in this package for `"skipped:`
// string literals. A hit outside the transient allow-list fails — the author
// must use notApplicable(reason) instead of minting a new silent success.
func TestNoSilentSkipSuccessReturns(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("matches-zero guard: no source files found — guard is not scanning anything")
	}

	var offending []string
	transientSeen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, `"skipped:`) && !strings.Contains(line, `("skipped:`) {
				continue
			}
			transient := false
			for _, marker := range transientSkipMarkers {
				if strings.Contains(line, marker) {
					transient = true
					transientSeen++
					break
				}
			}
			if !transient {
				offending = append(offending, fmt.Sprintf("%s:%d: %s", f, i+1, strings.TrimSpace(line)))
			}
		}
	}

	if len(offending) > 0 {
		t.Errorf("silent \"skipped:\" success returns found — use notApplicable(reason) for structural inapplicability (spec 23), or add a transient marker if this genuinely re-runs on the next reconciliation:\n%s",
			strings.Join(offending, "\n"))
	}
	// Matches-zero guard: the documented transient sites must still exist.
	// If they were renamed or moved, update transientSkipMarkers — a guard
	// matching nothing proves nothing.
	if transientSeen == 0 {
		t.Fatal("matches-zero guard: no transient skip sites matched transientSkipMarkers — update the markers to track the moved/renamed sites")
	}
}
