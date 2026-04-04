package store

import (
	"testing"
	"time"
)

func TestNextCronTime(t *testing.T) {
	loc := time.UTC
	ref := time.Date(2026, 4, 4, 10, 30, 0, 0, loc) // Friday 2026-04-04 10:30 UTC

	tests := []struct {
		name string
		expr string
		want time.Time
	}{
		{
			name: "every minute",
			expr: "* * * * *",
			want: time.Date(2026, 4, 4, 10, 31, 0, 0, loc),
		},
		{
			name: "daily at 3am",
			expr: "0 3 * * *",
			want: time.Date(2026, 4, 5, 3, 0, 0, 0, loc),
		},
		{
			name: "every 8 hours",
			expr: "0 */8 * * *",
			want: time.Date(2026, 4, 4, 16, 0, 0, 0, loc),
		},
		{
			name: "midnight daily",
			expr: "0 0 * * *",
			want: time.Date(2026, 4, 5, 0, 0, 0, 0, loc),
		},
		{
			name: "hourly at :00",
			expr: "0 * * * *",
			want: time.Date(2026, 4, 4, 11, 0, 0, 0, loc),
		},
		{
			name: "every 15 minutes",
			expr: "*/15 * * * *",
			want: time.Date(2026, 4, 4, 10, 45, 0, 0, loc),
		},
		{
			name: "sunday at 3am",
			expr: "0 3 * * 0",
			want: time.Date(2026, 4, 5, 3, 0, 0, 0, loc), // Apr 5 is Sunday
		},
		{
			name: "first of month at 3am",
			expr: "0 3 1 * *",
			want: time.Date(2026, 5, 1, 3, 0, 0, 0, loc),
		},
		{
			name: "weekdays at 9am",
			expr: "0 9 * * 1-5",
			want: time.Date(2026, 4, 6, 9, 0, 0, 0, loc), // Monday
		},
		{
			name: "specific minutes",
			expr: "15,45 * * * *",
			want: time.Date(2026, 4, 4, 10, 45, 0, 0, loc),
		},
		{
			name: "specific months jan and jul",
			expr: "0 0 1 1,7 *",
			want: time.Date(2026, 7, 1, 0, 0, 0, 0, loc),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nextCronTime(tt.expr, ref)
			if err != nil {
				t.Fatalf("nextCronTime(%q) error: %v", tt.expr, err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("nextCronTime(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestNextCronTime_Invalid(t *testing.T) {
	ref := time.Now()

	invalid := []string{
		"",
		"* * *",
		"* * * * * *",
		"60 * * * *",
		"* 25 * * *",
		"* * 32 * *",
		"* * * 13 *",
		"* * * * 7",
		"abc * * * *",
	}

	for _, expr := range invalid {
		_, err := nextCronTime(expr, ref)
		if err == nil {
			t.Errorf("nextCronTime(%q) expected error, got nil", expr)
		}
	}
}

func TestParseField(t *testing.T) {
	tests := []struct {
		field    string
		min, max int
		want     []int
	}{
		{"*", 0, 5, []int{0, 1, 2, 3, 4, 5}},
		{"*/2", 0, 5, []int{0, 2, 4}},
		{"1,3,5", 0, 5, []int{1, 3, 5}},
		{"1-3", 0, 5, []int{1, 2, 3}},
		{"0", 0, 59, []int{0}},
	}

	for _, tt := range tests {
		set, err := parseField(tt.field, tt.min, tt.max)
		if err != nil {
			t.Fatalf("parseField(%q, %d, %d) error: %v", tt.field, tt.min, tt.max, err)
		}
		for _, v := range tt.want {
			if !set[v] {
				t.Errorf("parseField(%q) missing %d", tt.field, v)
			}
		}
		if len(set) != len(tt.want) {
			t.Errorf("parseField(%q) got %d values, want %d", tt.field, len(set), len(tt.want))
		}
	}
}
