package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The R15 pin batch: the apply --json shape family (one encoder, real
// buckets on the empty branch, no text prefix under --json, both halves
// parse to one schema), the scan emitter's empty arrays, and the include
// refusal naming the shadowed fact through the pre-rail code.
func TestWiringR15ApplyJSONShapeFamily(t *testing.T) {
	// (a) The EXECUTED half: the default fixture's aged scratch-old is SAFE
	// and planned, so a --yes run deletes it; a smaller sibling stays below
	// a byte-scale --min-gb floor so BOTH buckets are live on one executed
	// run (round 16: excludedBytes must carry the real sum on this branch
	// too, not only on the empty half). Under --json, stdout must carry
	// ONLY the schema (the plan echo and preflight line moved to stderr)
	// and every list must be an array, never null.
	root, stateDir := wireFixture(t)
	tiny := filepath.Join(root, "tiny")
	if err := os.MkdirAll(tiny, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tiny, "x.bin"), make([]byte, 200), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, tiny, 40*24*time.Hour)
	writeWireConfig(t, stateDir, root)
	var js, e bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes", "--json", "--min-gb", "0.000002"}, &js, &e, os.Stdin); code != 0 {
		t.Fatalf("executed apply --json: %d (stderr %s json %s)", code, e.String(), js.String())
	}
	raw := strings.TrimSpace(js.String())
	if !strings.HasPrefix(raw, "{") {
		t.Fatalf("stdout under --json must carry ONLY the schema (found a text prefix):\n%s", js.String())
	}
	var executed map[string]any
	if err := json.Unmarshal([]byte(raw), &executed); err != nil {
		t.Fatalf("executed half is not valid JSON: %v\n%s", err, raw)
	}
	for _, list := range []string{"planned", "widened", "deleted", "skipped", "excludedBelowFloor", "excludedByCode"} {
		v, ok := executed[list]
		if !ok {
			t.Fatalf("executed half missing %s:\n%s", list, raw)
		}
		if _, isArray := v.([]any); !isArray {
			t.Fatalf("executed half %s must be an array, got %T (null?):\n%s", list, v, raw)
		}
	}
	if got := len(executed["deleted"].([]any)); got != 1 {
		t.Fatalf("deleted = %d, want the scratch dir:\n%s", got, raw)
	}
	// Round 16 value parity: the executed branch's excludedBytes equals the
	// below-bucket's real sum (it was always 0 before the fold).
	exBelow, _ := executed["excludedBelowFloor"].([]any)
	if len(exBelow) != 1 {
		t.Fatalf("the below-floor row must exist on the executed half too:\n%s", raw)
	}
	row, _ := exBelow[0].(map[string]any)
	sizeBytes, _ := row["sizeBytes"].(float64)
	excludedBytes, _ := executed["excludedBytes"].(float64)
	if excludedBytes != sizeBytes || excludedBytes <= 0 {
		t.Fatalf("excludedBytes (%v) must equal the below row's sizeBytes (%v) on the executed half:\n%s", excludedBytes, sizeBytes, raw)
	}

	// (b) The EMPTY half with REAL buckets: the same fixture under
	// --min-gb 5 pushes the 5KB scratch row below the floor - planned 0,
	// but the below-floor row and its bytes must survive (the hand-rolled
	// literal dropped them).
	root2, stateDir2 := wireFixture(t)
	writeWireConfig(t, stateDir2, root2)
	var js2 bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes", "--json", "--min-gb", "5"}, &js2, os.Stderr, os.Stdin); code != 0 {
		t.Fatalf("empty apply --json: %d (%s)", code, js2.String())
	}
	var empty map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(js2.String())), &empty); err != nil {
		t.Fatalf("empty half is not valid JSON: %v\n%s", err, js2.String())
	}
	if v, ok := empty["planned"].([]any); !ok || len(v) != 0 {
		t.Fatalf("planned must be an empty array, got %v:\n%s", empty["planned"], js2.String())
	}
	below, ok := empty["excludedBelowFloor"].([]any)
	if !ok || len(below) != 1 {
		t.Fatalf("the below-floor row must survive the empty branch (the literal dropped it): %v\n%s", empty["excludedBelowFloor"], js2.String())
	}
	if bz, ok := empty["excludedBytes"].(float64); !ok || bz < 1 {
		t.Fatalf("excludedBytes must carry the real bytes: %v\n%s", empty["excludedBytes"], js2.String())
	}

	// (c) The two halves parse to ONE schema: same key set, same list types.
	if len(executed) != len(empty) {
		t.Fatalf("key drift between the halves: executed %d keys, empty %d keys", len(executed), len(empty))
	}
	for k := range executed {
		if _, ok := empty[k]; !ok {
			t.Fatalf("key %s missing from the empty half:\n%s", k, js2.String())
		}
	}
}

// scan --json emits arrays (never null) on an empty scan, and the generated
// field parses RFC3339 - the format the plan/apply emitters use.
func TestWiringR15ScanJSONEmptyArrays(t *testing.T) {
	root, stateDir := wireFixture(t)
	emptyRoot := filepath.Join(root, "nothing")
	if err := os.MkdirAll(emptyRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	writeWireConfig(t, stateDir, emptyRoot)
	var js bytes.Buffer
	if code := cmdScan([]string{"--no-gh", "--json"}, &js, os.Stderr); code != ExitOK {
		t.Fatalf("scan --json: %d (%s)", code, js.String())
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(js.String()), &rep); err != nil {
		t.Fatalf("scan --json not valid: %v\n%s", err, js.String())
	}
	for _, list := range []string{"entries", "roots", "unreadableRoots"} {
		v, ok := rep[list]
		if !ok {
			t.Fatalf("missing %s:\n%s", list, js.String())
		}
		if _, isArray := v.([]any); !isArray {
			t.Fatalf("%s must be an array on an empty scan, got %T (null?)", list, v)
		}
	}
	totals, _ := rep["totals"].(map[string]any)
	if totals == nil {
		t.Fatalf("missing totals:\n%s", js.String())
	}
	if v, ok := totals["byReason"].([]any); !ok {
		t.Fatalf("byReason must be an array on an empty scan, got %T (null?)", totals["byReason"])
	} else if len(v) != 0 {
		t.Fatalf("byReason must be empty here, got %v", v)
	}
	g, _ := rep["generated"].(string)
	if g == "" {
		t.Fatalf("generated must be a string:\n%s", js.String())
	}
	if _, err := time.Parse(time.RFC3339, g); err != nil {
		t.Fatalf("generated must be RFC3339 (aligned with plan's emitter): %q: %v", g, err)
	}
}

// The include refusal names the path, the code, AND the shadowed fact for a
// railed row: a held dirty repo is refused BY NAME on --include
// dirty-files (the pre-rail association), never a silent 0.
func TestWiringR15IncludeRefusalNamesShadowedFact(t *testing.T) {
	root, stateDir := wireFixture(t)
	dirty := filepath.Join(root, "dirty")
	if err := os.MkdirAll(dirty, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, dirty, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dirty, "f.txt"), []byte("wip"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, dirty, 40*24*time.Hour)
	writeWireConfig(t, stateDir, root)
	if code := cmdHold([]string{"--for", "720h", dirty}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold: %d", code)
	}
	var e bytes.Buffer
	if code := cmdPlan([]string{"--no-gh", "--include", "dirty-files"}, &bytes.Buffer{}, &e); code != ExitUsage {
		t.Fatalf("held-dirty include: %d: %s", code, e.String())
	}
	for _, want := range []string{dirty, "dirty-files", "shadowed fact:", "dirty/untracked"} {
		if !strings.Contains(e.String(), want) {
			t.Fatalf("refusal must name the path, the code, and the shadowed fact (missing %q):\n%s", want, e.String())
		}
	}
}

// Round 16 scoping (the R15 board's reliability seat, live A/B): an include
// that DID plan deletable rows turns a railed sibling carrying the same code
// into a NOTE, not a whole-run refusal - the round-15 association briefly
// over-refused sanctioned mixed runs.
func TestWiringR16IncludeNoteNotRefusal(t *testing.T) {
	root, stateDir := wireFixture(t)
	// Two scratch-recent dirs (10d idle: judgment-class MANUAL). One held.
	legit := filepath.Join(root, "legit")
	if err := os.MkdirAll(legit, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legit, "x.bin"), make([]byte, 3000), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, legit, 10*24*time.Hour)
	ageTree(t, filepath.Join(root, "scratch-old"), 10*24*time.Hour) // second carrier, also recent now
	writeWireConfig(t, stateDir, root)
	if code := cmdHold([]string{"--for", "720h", filepath.Join(root, "scratch-old")}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold: %d", code)
	}
	var out, e bytes.Buffer
	if code := cmdPlan([]string{"--no-gh", "--include", "scratch-recent"}, &out, &e); code != ExitOK {
		t.Fatalf("mixed include must PROCEED (the legit row plans): %d: %s / %s", code, out.String(), e.String())
	}
	if !strings.Contains(out.String(), legit) {
		t.Fatalf("the legit scratch-recent row must be planned:\n%s", out.String())
	}
	if !strings.Contains(e.String(), "note:") || !strings.Contains(e.String(), "scratch-old") {
		t.Fatalf("the held sibling must be a NOTE naming it:\n%s", e.String())
	}
}

// Round 16 family match: `--include active` on rows displaying a sibling
// ACTIVE spelling (scratch-fresh) is the named usage error, not a silent 0.
func TestWiringR16IncludeActiveFamilyRefusal(t *testing.T) {
	root, stateDir := wireFixture(t)
	fresh := filepath.Join(root, "fresh")
	if err := os.MkdirAll(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fresh, "x.bin"), make([]byte, 100), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, fresh, 3*24*time.Hour) // past the 48h activity rail, under the 7d scratch floor: scratch-fresh (the sibling spelling)
	writeWireConfig(t, stateDir, root)
	var e bytes.Buffer
	if code := cmdPlan([]string{"--no-gh", "--include", "active"}, &bytes.Buffer{}, &e); code != ExitUsage {
		t.Fatalf("sibling-spelling include: %d (want the named 120): %s", code, e.String())
	}
	if !strings.Contains(e.String(), fresh) || !strings.Contains(e.String(), "scratch-fresh") {
		t.Fatalf("the refusal must name the sibling-coded row:\n%s", e.String())
	}
}
