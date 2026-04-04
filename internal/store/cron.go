package store

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// nextCronTime parses a standard 5-field cron expression and returns the next
// execution time after the given reference time.
//
// Format: minute hour day-of-month month day-of-week
// Supports: numbers, *, */N, N-M, comma-separated lists.
func nextCronTime(expr string, after time.Time) (time.Time, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Time{}, fmt.Errorf("expected 5 fields, got %d", len(fields))
	}

	minutes, err := parseField(fields[0], 0, 59)
	if err != nil {
		return time.Time{}, fmt.Errorf("minute: %w", err)
	}
	hours, err := parseField(fields[1], 0, 23)
	if err != nil {
		return time.Time{}, fmt.Errorf("hour: %w", err)
	}
	doms, err := parseField(fields[2], 1, 31)
	if err != nil {
		return time.Time{}, fmt.Errorf("day-of-month: %w", err)
	}
	months, err := parseField(fields[3], 1, 12)
	if err != nil {
		return time.Time{}, fmt.Errorf("month: %w", err)
	}
	dows, err := parseField(fields[4], 0, 6)
	if err != nil {
		return time.Time{}, fmt.Errorf("day-of-week: %w", err)
	}

	domWild := isFullRange(doms, 1, 31)
	dowWild := isFullRange(dows, 0, 6)

	// Start searching from one minute after the reference time
	t := after.Truncate(time.Minute).Add(time.Minute)

	// Search up to 366 days ahead to avoid infinite loops
	limit := t.Add(366 * 24 * time.Hour)

	for t.Before(limit) {
		if !months[int(t.Month())] {
			// Skip to next month
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
			continue
		}

		dayMatch := false
		if domWild && dowWild {
			dayMatch = true
		} else if domWild {
			dayMatch = dows[int(t.Weekday())]
		} else if dowWild {
			dayMatch = doms[t.Day()]
		} else {
			// When both are specified, cron uses OR (either matches)
			dayMatch = doms[t.Day()] || dows[int(t.Weekday())]
		}

		if !dayMatch {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
			continue
		}

		if !hours[t.Hour()] {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
			continue
		}

		if !minutes[t.Minute()] {
			t = t.Add(time.Minute)
			continue
		}

		return t, nil
	}

	return time.Time{}, fmt.Errorf("no matching time found within 366 days")
}

// parseField parses a cron field into a boolean set of allowed values.
// Supports: *, */N, N, N-M, comma-separated combinations.
func parseField(field string, min, max int) (map[int]bool, error) {
	set := make(map[int]bool)

	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)

		if part == "*" {
			for i := min; i <= max; i++ {
				set[i] = true
			}
			continue
		}

		if strings.HasPrefix(part, "*/") {
			step, err := strconv.Atoi(part[2:])
			if err != nil || step <= 0 {
				return nil, fmt.Errorf("invalid step %q", part)
			}
			for i := min; i <= max; i += step {
				set[i] = true
			}
			continue
		}

		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			hi, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			if lo < min || hi > max || lo > hi {
				return nil, fmt.Errorf("range %q out of bounds [%d-%d]", part, min, max)
			}
			for i := lo; i <= hi; i++ {
				set[i] = true
			}
			continue
		}

		val, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid value %q", part)
		}
		if val < min || val > max {
			return nil, fmt.Errorf("value %d out of bounds [%d-%d]", val, min, max)
		}
		set[val] = true
	}

	if len(set) == 0 {
		return nil, fmt.Errorf("empty field")
	}
	return set, nil
}

// isFullRange returns true if the set contains every value in [min, max].
// Used to detect wildcard-equivalent patterns like */1 or 0-6.
func isFullRange(set map[int]bool, min, max int) bool {
	for i := min; i <= max; i++ {
		if !set[i] {
			return false
		}
	}
	return true
}
