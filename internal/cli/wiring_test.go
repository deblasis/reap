package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deblasis/reap/internal/applycmd"
)

// The wiring layer (cmdPlan/cmdApply/cmdHold/cmdUnhold/cmdHolds) is where
// every inert disposition across four review rounds lived. These tests
// execute the CLI surface end-to-end through the same entry points
// production uses.

func wireFixture(t *testing.T) (root, stateDir string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	stateDir = filepath.Join(base, "state")
	for _, d := range []string{filepath.Join(root, "scratch-old"), stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(root, "scratch-old")
	if err := os.WriteFile(filepath.Join(old, "junk1.bin"), make([]byte, 3000), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "junk2.bin"), make([]byte, 2000), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().AddDate(0, 0, -40)
	filepath.WalkDir(old, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			os.Chtimes(p, past, past)
		}
		return nil
	})
	writeWireConfig(t, stateDir, root)
	return root, stateDir
}

func writeWireConfig(t *testing.T, stateDir, root string) {
	t.Helper()
	cfg := `{
  "roots": ["` + filepath.ToSlash(root) + `"],
  "protect": [],
  "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21, "remote-stale-hours": 72, "quarantine-cap-gb": 2, "quarantine-retention-days": 30, "quarantine-margin": 2.5, "min-free-mb": 256, "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"},
  "gh": false,
  "jj": true
}`
	if err := os.WriteFile(filepath.Join(stateDir, "config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REAP_DIR", stateDir)
}

// Hold -> hold -> holds -> unhold lifecycle through the command layer,
// including the corrupt-file refusal (round 1's brick).
func TestWiringHoldsLifecycle(t *testing.T) {
	root, stateDir := wireFixture(t)
	target := filepath.Join(root, "scratch-old")

	if code := cmdHold([]string{"--for", "168h", target}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold: %d", code)
	}
	second := filepath.Join(root, "other")
	if code := cmdHold([]string{"--for", "24h", second}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold 2: %d", code)
	}
	var out bytes.Buffer
	if code := cmdHolds(nil, &out, os.Stderr); code != ExitOK {
		t.Fatalf("holds: %d", code)
	}
	if !strings.Contains(out.String(), "scratch-old") || !strings.Contains(out.String(), "other") {
		t.Fatalf("holds output: %q", out.String())
	}
	// Scan stays healthy with holds present.
	if code := cmdScan([]string{"--no-gh", "--json"}, &bytes.Buffer{}, os.Stderr); code != ExitOK {
		t.Fatalf("scan with holds: %d", code)
	}
	// Corrupt holds.json: hold refuses (122), file untouched.
	if err := os.WriteFile(filepath.Join(stateDir, "holds.json"), []byte("GARBAGE{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdHold([]string{"--for", "24h", second}, os.Stdout, os.Stderr); code != ExitState {
		t.Fatalf("corrupt hold must 122, got %d", code)
	}
	if b, _ := os.ReadFile(filepath.Join(stateDir, "holds.json")); string(b) != "GARBAGE{" {
		t.Fatalf("corrupt file was rewritten: %q", b)
	}
	// Restore a valid two-hold file (the refusal left GARBAGE in place),
	// via the real writer — hand-built JSON with raw Windows backslashes is
	// invalid JSON, which is itself the corrupt case under test.
	far := time.Now().Add(100 * 365 * 24 * time.Hour)
	if err := applycmd.WriteHolds(stateDir, map[string]time.Time{target: far, second: far}); err != nil {
		t.Fatal(err)
	}
	if code := cmdUnhold([]string{filepath.Join(root, "never-held")}, os.Stdout, os.Stderr); code != ExitUsage {
		t.Fatalf("unhold unknown: %d", code)
	}
	if code := cmdUnhold([]string{target}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("unhold: %d", code)
	}
	out.Reset()
	cmdHolds(nil, &out, os.Stderr)
	if strings.Contains(out.String(), "no holds") == false && strings.Contains(out.String(), "scratch-old") {
		t.Fatalf("target still listed: %q", out.String())
	}
}

// Plan vs apply --dry-run byte-identity in text mode (the spec's tie).
func TestWiringPlanDryRunIdentity(t *testing.T) {
	_, _ = wireFixture(t)
	var plan, dry bytes.Buffer
	if code := cmdPlan([]string{"--no-gh"}, &plan, os.Stderr); code != ExitOK {
		t.Fatalf("plan: %d", code)
	}
	if code := cmdApply([]string{"--no-gh", "--dry-run"}, &dry, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("dry-run: %d", code)
	}
	if plan.String() != dry.String() {
		t.Fatalf("byte-identity broken:\nplan: %q\ndry:  %q", plan.String(), dry.String())
	}
	if !strings.Contains(plan.String(), "scratch-old") {
		t.Fatalf("scratch dir missing from plan: %q", plan.String())
	}
}

// A real apply through the command layer: the scratch dir is deleted, the
// audit ledger has intent-before/result-after with a REAL manifest (not
// the unreadable stub), and the envelope closes the session.
func TestWiringApplyDeletesWithManifest(t *testing.T) {
	root, stateDir := wireFixture(t)
	target := filepath.Join(root, "scratch-old")
	var out bytes.Buffer
	code := cmdApply([]string{"--no-gh", "--yes"}, &out, os.Stderr, os.Stdin)
	if code != ExitOK {
		t.Fatalf("apply: %d (%s)", code, out.String())
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("scratch dir survived apply")
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 3 {
		t.Fatalf("ledger too short: %d lines", len(lines))
	}
	var intent, result, envelope map[string]any
	json.Unmarshal([]byte(lines[0]), &intent)
	json.Unmarshal([]byte(lines[1]), &result)
	json.Unmarshal([]byte(lines[len(lines)-1]), &envelope)
	if intent["event"] != "intent" || result["event"] != "result" {
		t.Fatalf("write-ahead order: %v then %v", intent["event"], result["event"])
	}
	if intent["ts"].(string) > result["ts"].(string) {
		t.Fatal("intent not ahead of result")
	}
	if result["ok"] != true {
		t.Fatalf("result ok: %v", result["ok"])
	}
	// The manifest must decode to real entries (the round-2 stub bug).
	mb, _ := base64.StdEncoding.DecodeString(result["manifest"].(string))
	if !strings.Contains(string(mb), "junk1.bin") {
		t.Fatalf("manifest missing real entries: %q", string(mb))
	}
	if envelope["event"] != "envelope" || envelope["deleted"].(float64) < 1 {
		t.Fatalf("envelope: %v", envelope)
	}
}

// Exit-band routing at the command layer: bare unhold is a usage error,
// unknown include codes are usage errors, and the non-TTY orphaned
// --override-manual refusal lands in 121 (carve-out interim).
func TestWiringExitBand(t *testing.T) {
	root, _ := wireFixture(t)
	if code := cmdUnhold(nil, os.Stdout, os.Stderr); code != ExitUsage {
		t.Fatalf("bare unhold: %d", code)
	}
	if code := cmdPlan([]string{"--no-gh", "--include", "not-a-code"}, os.Stdout, os.Stderr); code != ExitUsage {
		t.Fatalf("unknown code: %d", code)
	}
	// Orphaned worktree + --override-manual --yes, non-TTY: 121.
	base := filepath.Dir(root)
	ph := filepath.Join(base, "porph")
	if out, err := exec.Command("git", "init", "-q", "-b", "main", ph).CombinedOutput(); err != nil {
		t.Skipf("git init: %v %s", err, out)
	}
	wt := filepath.Join(base, "orphan-wt")
	if out, err := exec.Command("git", "-C", ph, "worktree", "add", "-q", wt).CombinedOutput(); err != nil {
		t.Skipf("worktree add: %v %s", err, out)
	}
	os.RemoveAll(ph)
	// Age the whole worktree: fresh files would verdict ACTIVE, and the
	// refusal path only triggers for MANUAL orphaned rows.
	past2 := time.Now().AddDate(0, 0, -30)
	filepath.WalkDir(wt, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			os.Chtimes(p, past2, past2)
		}
		return nil
	})
	// Re-point the fixture root so the orphan is a candidate.
	writeWireConfig(t, filepath.Join(filepath.Dir(root), "state"), base)
	if code := cmdApply([]string{"--no-gh", "--yes", "--override-manual", wt}, os.Stdout, os.Stderr, os.Stdin); code != applycmd.ExitNotTTY {
		t.Fatalf("orphan non-TTY --yes: %d (want 121)", code)
	}
	if _, err := os.Stat(wt); err != nil {
		t.Fatal("orphaned dir was deleted")
	}
}
