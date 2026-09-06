package auditlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Write-ahead is the package's whole contract: an intent line for every
// deletion exists in the file BEFORE the deletion result line, and an
// append failure surfaces as an error (apply aborts on it).
func TestWriteAheadOrdering(t *testing.T) {
	dir := t.TempDir()
	log, err := Open(dir, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	ok := true
	if err := log.Append(Line{Event: "intent", Path: `C:\x\a`, Verdict: "SAFE", ReasonCode: "clean-pushed", Quarantine: nil}); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(Line{Event: "result", Path: `C:\x\a`, Mode: "rm", OK: &ok, Quarantine: nil}); err != nil {
		t.Fatal(err)
	}
	if err := log.Append(Line{Event: "envelope", Planned: 1, Deleted: 1, Skipped: 0, FreeBefore: 1, FreeAfter: 2, Quarantine: nil}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "reap.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	var first, last Line
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[2]), &last); err != nil {
		t.Fatal(err)
	}
	if first.Event != "intent" || first.RunID != "run-1" || first.TS == "" {
		t.Fatalf("intent line = %+v", first)
	}
	if last.Event != "envelope" || last.Deleted != 1 || last.FreeAfter != 2 {
		t.Fatalf("envelope = %+v", last)
	}
	// quarantinePath serializes as null, not absent (schema contract);
	// encoding/json writes no space after the colon.
	if !strings.Contains(string(raw), `"quarantinePath":null`) {
		t.Fatal("quarantinePath must serialize null")
	}
}

// Rotation at the bound keeps the ledger bounded without splitting the
// current file mid-write.
func TestRotationAtBound(t *testing.T) {
	dir := t.TempDir()
	log, err := Open(dir, "run-r")
	if err != nil {
		t.Fatal(err)
	}
	// Cross the bound with few, large lines (8MB each: 7 appends cross 50MB).
	big := strings.Repeat("x", 8<<20)
	for i := 0; i < 7; i++ {
		if err := log.Append(Line{Event: "intent", Path: "padding", Manifest: []byte(big), Quarantine: nil}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "reap.log.1")); err != nil {
		t.Fatalf("rotation did not occur: %v", err)
	}
	// The active log exists and is under the bound.
	fi, err := os.Stat(filepath.Join(dir, "reap.log"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() >= rotationBound {
		t.Fatalf("active log still over bound: %d", fi.Size())
	}
}

func TestNewRunIDShape(t *testing.T) {
	id := NewRunID()
	if !strings.HasPrefix(id, "reap-") || len(id) < 15 {
		t.Fatalf("runID = %q", id)
	}
}
