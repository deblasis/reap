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
	// and planned, so a --yes run deletes it. Under --json, stdout must
	// carry ONLY the schema (the plan echo and preflight line moved to
	// stderr) and every list must be an array, never null.
	root, stateDir := wireFixture(t)
	writeWireConfig(t, stateDir, root)
	var js, e bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes", "--json"}, &js, &e, os.Stdin); code != 0 {
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
