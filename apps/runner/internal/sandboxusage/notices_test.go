// SPDX-License-Identifier: AGPL-3.0

package sandboxusage

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func readNotices(t *testing.T, dir, id string) ([]any, bool) {
	t.Helper()
	v, ok := readEnv(t, dir, id)["notices"]
	if !ok {
		return nil, false
	}
	return v.([]any), true
}

func TestNotices_ShownUntilTheyLapse(t *testing.T) {
	f := newFixture(t)
	dir := withEnvDir(t, f)
	f.c.refresh(context.Background())
	if _, ok := readNotices(t, dir, "sb-run"); ok {
		t.Fatal("notices shown before billing sent any")
	}

	deadline := time.Date(2026, 11, 24, 15, 30, 0, 0, time.FixedZone("x", 3600))
	err := f.c.SetNotices(map[string][]Notice{
		"sb-run": {{Kind: "disk_over_size", Severity: "critical", Message: "Delete files.", Deadline: &deadline, Action: "stop"}},
		"sb-new": {{Kind: "balance_low", Severity: "warning", Message: "Top up."}},
	}, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Written at once, not on the next refresh.
	ns, ok := readNotices(t, dir, "sb-run")
	if !ok || len(ns) != 1 {
		t.Fatalf("notices = %v, %v", ns, ok)
	}
	n := ns[0].(map[string]any)
	if n["kind"] != "disk_over_size" || n["severity"] != "critical" || n["message"] != "Delete files." ||
		n["deadline"] != "2026-11-24T14:30:00Z" || n["action"] != "stop" {
		t.Errorf("notice = %v", n)
	}

	// A set without the sandbox: an empty list, nothing to warn about.
	if err := f.c.SetNotices(map[string][]Notice{}, 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	if ns, ok := readNotices(t, dir, "sb-run"); !ok || len(ns) != 0 {
		t.Errorf("notices after a set without the sandbox = %v, %v; want []", ns, ok)
	}

	// Billing stopped sending: the set lapses.
	f.now = f.now.Add(3 * time.Minute)
	f.c.refresh(context.Background())
	if ns, ok := readNotices(t, dir, "sb-run"); ok {
		t.Errorf("notices after the set lapsed = %v; want none", ns)
	}
}

func TestNotices_InvalidSetsRejectedWhole(t *testing.T) {
	f := newFixture(t)
	dir := withEnvDir(t, f)
	f.c.refresh(context.Background())
	ok := Notice{Kind: "maintenance", Severity: "info", Message: "Restart at noon."}
	if err := f.c.SetNotices(map[string][]Notice{"sb-run": {ok}}, time.Minute); err != nil {
		t.Fatal(err)
	}

	many := make([]Notice, maxNoticesPerSandbox+1)
	for i := range many {
		many[i] = ok
	}
	for name, tc := range map[string]struct {
		set      map[string][]Notice
		validFor time.Duration
	}{
		"no validity":       {map[string][]Notice{"sb-run": {ok}}, 0},
		"validity too long": {map[string][]Notice{"sb-run": {ok}}, 2 * time.Hour},
		"path in the ID":    {map[string][]Notice{"../sb-run": {ok}}, time.Minute},
		"too many":          {map[string][]Notice{"sb-run": many}, time.Minute},
		"kind":              {map[string][]Notice{"sb-run": {{Kind: "Disk Full", Severity: "info", Message: "x"}}}, time.Minute},
		"severity":          {map[string][]Notice{"sb-run": {{Kind: "x", Severity: "fatal", Message: "x"}}}, time.Minute},
		"no message":        {map[string][]Notice{"sb-run": {{Kind: "x", Severity: "info"}}}, time.Minute},
		"long message":      {map[string][]Notice{"sb-run": {{Kind: "x", Severity: "info", Message: strings.Repeat("x", maxNoticeMessage+1)}}}, time.Minute},
		"action":            {map[string][]Notice{"sb-run": {{Kind: "x", Severity: "info", Message: "x", Action: "rm -rf"}}}, time.Minute},
		"one bad of two":    {map[string][]Notice{"sb-run": {ok}, "sb-stop": {{Kind: "", Severity: "info", Message: "x"}}}, time.Minute},
	} {
		if err := f.c.SetNotices(tc.set, tc.validFor); !errors.Is(err, ErrInvalidNotices) {
			t.Errorf("%s: err = %v, want ErrInvalidNotices", name, err)
		}
	}
	// The valid set before them still stands.
	if ns, ok := readNotices(t, dir, "sb-run"); !ok || len(ns) != 1 {
		t.Errorf("notices after rejected sets = %v, %v; want the earlier one", ns, ok)
	}
}

func TestNotices_OffWithoutEnvDir(t *testing.T) {
	f := newFixture(t)
	if err := f.c.SetNotices(map[string][]Notice{}, time.Minute); !errors.Is(err, ErrNoticesOff) {
		t.Errorf("err = %v, want ErrNoticesOff", err)
	}
}
