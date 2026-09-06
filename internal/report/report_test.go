package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func entry(v, code string, bytes int64, path string) Entry {
	return Entry{Path: path, Verdict: v, ReasonCode: code, SizeBytes: bytes, Reason: code + " reason"}
}

func build(entries ...Entry) *ScanReport {
	return Build(time.Now(), []RootSummary{{Path: "C:\\temp", Dirs: len(entries)}}, entries, 0)
}

// Section order is the spec's mock: ACTIVE first, BLOCKED second (the
// resolution queue IS the product), MANUAL, KEEP, SAFE LAST as the payoff.
func TestTableSectionOrder(t *testing.T) {
	blocked := entry("BLOCKED", "dirty-files", 4<<30, `C:\t\blocked`)
	blocked.Hint = "commit+push the work"
	r := build(
		entry("SAFE", "clean-pushed", 1<<30, `C:\t\safe`),
		entry("KEEP", "protected", 2<<30, `C:\t\kept`),
		entry("MANUAL", "scratch-recent", 3<<30, `C:\t\manual`),
		blocked,
		entry("ACTIVE", "active", 5<<30, `C:\t\active`),
	)
	var buf bytes.Buffer
	r.Table(&buf)
	s := buf.String()
	order := []string{"ACTIVE", "BLOCKED", "MANUAL", "KEEP", "SAFE"}
	last := -1
	for _, sect := range order {
		i := strings.Index(s, sect)
		if i < 0 {
			t.Fatalf("section %s missing", sect)
		}
		if i < last {
			t.Fatalf("section %s out of order:\n%s", sect, s)
		}
		last = i
	}
	for _, want := range []string{"sizes are logical", "hint: commit+push the work"} {
		if !strings.Contains(s, want) {
			t.Errorf("table missing %q", want)
		}
	}
}

// Hints render on BLOCKED and MANUAL rows only; elision kicks in past 15
// (rows are size-desc, so the hinted row must be the largest to stay shown).
func TestTableHintsAndElision(t *testing.T) {
	var entries []Entry
	for i := 0; i < 20; i++ {
		e := entry("BLOCKED", "dirty-files", int64(i+1)<<20, `C:\t\b`)
		if i == 19 { // largest: sorted first, within the shown 15
			e.Hint = "commit+push the work"
		}
		entries = append(entries, e)
	}
	r := build(entries...)
	var buf bytes.Buffer
	r.Table(&buf)
	s := buf.String()
	if !strings.Contains(s, "hint: commit+push the work") {
		t.Error("BLOCKED row hint must render")
	}
	if !strings.Contains(s, "+5 more, use --json") {
		t.Error("elision footer missing (20 rows, 15 shown, 5 elided)")
	}
	// KEEP/SAFE rows never print hint lines.
	var keepBuf bytes.Buffer
	build(entry("SAFE", "clean-pushed", 1<<30, `C:\t\s`)).Table(&keepBuf)
	if strings.Contains(keepBuf.String(), "hint:") {
		t.Error("SAFE rows must not print hints")
	}
}

// byReason totals print in the table and land in JSON sorted by size.
func TestByReasonTotals(t *testing.T) {
	r := build(
		entry("BLOCKED", "dirty-files", 2<<30, `C:\t\a`),
		entry("BLOCKED", "dirty-files", 1<<30, `C:\t\b`),
		entry("MANUAL", "scratch-recent", 1<<30, `C:\t\c`),
	)
	if len(r.Totals.ByReason) != 2 {
		t.Fatalf("byReason = %+v", r.Totals.ByReason)
	}
	if r.Totals.ByReason[0].Code != "dirty-files" || r.Totals.ByReason[0].Dirs != 2 {
		t.Fatalf("byReason[0] = %+v, want dirty-files x2 first (size-desc)", r.Totals.ByReason[0])
	}
	var buf bytes.Buffer
	r.Table(&buf)
	if !strings.Contains(buf.String(), "dirty-files") {
		t.Error("byReason must print in the table")
	}
}

// The --json wire shape: openPR always present, nullable fields as null,
// reclaimableGB null, sizes "logical", excluded counted not listed.
func TestJSONShape(t *testing.T) {
	// min-gb 1: the 1-byte SAFE entry drops from the LISTING (but still
	// counts in totals) — the spec's report-only floor contract.
	r := Build(time.Now(),
		[]RootSummary{{Path: "C:\\temp", Dirs: 2}},
		[]Entry{
			entry("BLOCKED", "dirty-files", 1<<30, `C:\t\a`),
			entry("SAFE", "scratch-idle", 1, `C:\t\tiny`),
		}, 1.0)
	var buf bytes.Buffer
	if err := r.JSON(&buf); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{
		`"openPR": false`,
		`"lineageGroup": null`,
		`"downgradedBy": null`,
		`"reclaimableGB": null`,
		`"sizes": "logical"`,
		`"excludedBelowMinGB": 1`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON missing %s\n%s", want, s)
		}
	}
	var back ScanReport
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if len(back.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (tiny excluded from listing)", len(back.Entries))
	}
	// The excluded entry still counts in totals (its GB rounds to 0.0, so
	// assert via the byReason count, not SafeGB).
	counted := false
	for _, bt := range back.Totals.ByReason {
		if bt.Code == "scratch-idle" && bt.Dirs == 1 {
			counted = true
		}
	}
	if !counted {
		t.Fatalf("excluded entry must still count in totals: %+v", back.Totals.ByReason)
	}
}
