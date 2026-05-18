package handler

// Tests for the agent log-filter helpers introduced for audit
// F-32 (stdout/stderr redaction + truncation) and the regex
// complexity guard introduced for F-35 (journalctl --grep ReDoS).

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeForLog(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		contains string
		excludes []string
	}{
		{
			name:     "empty stays empty",
			in:       "",
			contains: "",
		},
		{
			name:     "short ok line passes through",
			in:       "all good",
			contains: "all good",
		},
		{
			name:     "long line gets truncation marker",
			in:       strings.Repeat("x", 1024),
			contains: "[truncated by agent log filter]",
		},
		{
			name:     "enc:v1 ciphertext redacted",
			in:       "client_secret = enc:v1:abcdefGHIJklmn+/== rest of line",
			contains: "[REDACTED-ENC]",
			excludes: []string{"abcdefGHIJklmn", "enc:v1:"},
		},
		{
			name:     "multiple enc:v1 markers all redacted",
			in:       "a=enc:v1:AAA b=enc:v1:BBBccc done",
			contains: "[REDACTED-ENC]",
			excludes: []string{"AAA", "BBBccc"},
		},
		{
			name:     "enc:v1 followed by non-base64 char stops cleanly",
			in:       "before enc:v1:abc!end",
			contains: "[REDACTED-ENC]",
			excludes: []string{"enc:v1:abc"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := sanitizeForLog(tc.in)
			if tc.contains != "" {
				assert.Contains(t, out, tc.contains)
			}
			for _, ex := range tc.excludes {
				assert.NotContains(t, out, ex, "redacted output must not contain %q", ex)
			}
			assert.LessOrEqual(t, len(out), maxLogOutputBytes+len("... [truncated by agent log filter]"),
				"length never exceeds cap + marker")
		})
	}
}

func TestIsPathologicalGrepPattern(t *testing.T) {
	cases := []struct {
		name      string
		pattern   string
		wantEmpty bool // true → pattern is OK (returns "")
	}{
		// Healthy patterns
		{"plain literal", "ERROR", true},
		{"anchored literal", "^kernel: error", true},
		{"bounded quantifier", "a{3,5}b", true},
		{"single unbounded quantifier", "a+b", true},
		{"alternation outside quantifier", "warn|error|fail", true},
		{"escaped paren is literal", `\(group\)+`, true},
		// Pathological — nested unbounded quantifier
		{"classic (a+)+ ReDoS shape", "(a+)+b", false},
		{"(a*)* ReDoS shape", "(a*)*", false},
		{"(a{1,})+ ReDoS shape", "(a{1,})+", false},
		// Pathological — alternation under unbounded quantifier
		{"(a|a)+ exponential", "(a|a)+", false},
		{"(a|ab)+ ambiguous", "(a|ab)+x", false},
		// Pathological — too many unbounded quantifiers stacked
		{"staircase of *'s", "a*b*c*d*e*f*g*", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason := isPathologicalGrepPattern(tc.pattern)
			if tc.wantEmpty {
				assert.Equal(t, "", reason, "pattern %q should be accepted but was rejected: %s", tc.pattern, reason)
			} else {
				assert.NotEqual(t, "", reason, "pattern %q should be rejected as pathological", tc.pattern)
			}
		})
	}
}

func TestQuantifierUnbounded(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"{3,}", true},
		{"{3,5}", false},
		{"{3}", false},
		{"{,5}", false},
		{"", false},
		{"a{3,}", false}, // not starting at the `{`
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, quantifierUnbounded(tc.in))
		})
	}
}
