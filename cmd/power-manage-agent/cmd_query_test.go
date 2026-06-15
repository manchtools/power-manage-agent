package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/sys/osquery"
)

// WS16 #13: the install-guidance branch must fire even when the
// osquery.ErrNotInstalled sentinel is wrapped. isNotInstalled extracts the
// predicate so it is testable and uses errors.Is.
func TestIsNotInstalled(t *testing.T) {
	if !isNotInstalled(osquery.ErrNotInstalled) {
		t.Error("bare sentinel must be detected as not-installed")
	}
	if !isNotInstalled(fmt.Errorf("create registry: %w", osquery.ErrNotInstalled)) {
		t.Error("wrapped sentinel must still be detected (errors.Is, not ==)")
	}
	if isNotInstalled(errors.New("permission denied")) {
		t.Error("an unrelated error must not be treated as not-installed")
	}
	if isNotInstalled(nil) {
		t.Error("nil must not be treated as not-installed")
	}
}
