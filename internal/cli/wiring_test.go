package cli

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deblasis/reap/internal/applycmd"
	"github.com/deblasis/reap/internal/quarantine"
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
	ageTree(t, wt, 30*24*time.Hour)
	// Re-point the fixture root so the orphan is a candidate.
	writeWireConfig(t, filepath.Join(filepath.Dir(root), "state"), base)
	if code := cmdApply([]string{"--no-gh", "--yes", "--override-manual", wt}, os.Stdout, os.Stderr, os.Stdin); code != applycmd.ExitNotTTY {
		t.Fatalf("orphan non-TTY --yes: %d (want 121)", code)
	}
	if _, err := os.Stat(wt); err != nil {
		t.Fatal("orphaned dir was deleted")
	}
}

// --- M3: discard / quarantine / log / doctor wiring ---

func wireGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// ageTree backdates every file and dir (incl. .git internals) so the walk
// tripwire and activity floors see an idle tree.
func ageTree(t *testing.T, root string, ago time.Duration) {
	t.Helper()
	past := time.Now().Add(-ago)
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			os.Chtimes(p, past, past)
		}
		return nil
	})
}

// The discard happy path END TO END: a dirty no-remote repo (the canonical
// BLOCKED shape) is quarantined into a session holding a REAL bundle, the
// dir is deleted, the ledger carries intent-before/result-after with the
// quarantine pointer, and RECOVERY IS PROVEN by fetching the bundle into a
// fresh repo and reading the dirty content out of the capture ref.
func TestWiringDiscardE2E(t *testing.T) {
	root, stateDir := wireFixture(t)
	repo := filepath.Join(root, "blocked-dirty")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "add", "-A")
	wireGit(t, repo, "commit", "-q", "-m", "one")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("modified"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("u"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, repo, 30*24*time.Hour)

	var out bytes.Buffer
	if code := cmdDiscard([]string{"--yes", repo}, &out, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("discard: %d (%s / %s)", code, out.String(), "see stderr")
	}
	if _, err := os.Stat(repo); !os.IsNotExist(err) {
		t.Fatal("blocked dir survived discard")
	}

	// Exactly one session, holding manifest + bundle.
	qdir := filepath.Join(stateDir, "quarantine")
	entries, err := os.ReadDir(qdir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("quarantine sessions: %v (%v)", len(entries), err)
	}
	session := filepath.Join(qdir, entries[0].Name())
	mraw, err := os.ReadFile(filepath.Join(session, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := quarantine.Manifest{}
	if err := json.Unmarshal(mraw, &m); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if m.Mode != "bundle" || m.BundleBytes == 0 || m.CaptureRef == "" {
		t.Fatalf("manifest incomplete: %+v", m)
	}
	if m.Classes.DirtyFiles < 1 || m.Classes.Refs < 1 {
		t.Fatalf("manifest classes: %+v", m.Classes)
	}
	if fi, err := os.Stat(filepath.Join(session, "bundle.git")); err != nil || fi.Size() == 0 {
		t.Fatalf("bundle.git missing/empty: %v", err)
	}

	// Ledger: intent before result; result carries ok + quarantinePath.
	raw, err := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 3 {
		t.Fatalf("ledger too short: %d", len(lines))
	}
	var intent, result map[string]any
	json.Unmarshal([]byte(lines[0]), &intent)
	json.Unmarshal([]byte(lines[1]), &result)
	if intent["event"] != "intent" || result["event"] != "result" {
		t.Fatalf("write-ahead order: %v then %v", intent["event"], result["event"])
	}
	if result["ok"] != true {
		t.Fatalf("result ok: %v", result["ok"])
	}
	qp, _ := result["quarantinePath"].(string)
	if qp == "" || !strings.HasPrefix(filepath.Clean(qp), filepath.Clean(qdir)) {
		t.Fatalf("result quarantinePath: %q", qp)
	}
	// The result manifest names the untracked file: recoverability must be
	// legible from the ledger alone.
	if mb, ok := result["manifest"].(string); ok {
		dec, derr := base64.StdEncoding.DecodeString(mb)
		if derr != nil || !strings.Contains(string(dec), "untracked.txt") {
			t.Fatalf("ledger manifest missing the untracked file: %v %q", derr, dec)
		}
	} else {
		t.Fatal("result line missing manifest")
	}

	// Recovery proof: fetch the bundle into a fresh repo; the capture ref's
	// tree holds the dirty content. This is the whole contract.
	rec := t.TempDir()
	wireGit(t, rec, "init", "-q", "-b", "main")
	wireGit(t, rec, "fetch", "-q", filepath.Join(session, "bundle.git"), "refs/reap/*:refs/reap/*")
	shown := wireGit(t, rec, "show", m.CaptureRef+":f.txt")
	if !strings.Contains(shown, "modified") {
		t.Fatalf("capture ref does not hold the dirty content: %q", shown)
	}
}

// discard refuses anything that is not BLOCKED: a clean, pushed repo is
// SAFE and must survive with a skip line, exit 2.
func TestWiringDiscardRefusesNotBlocked(t *testing.T) {
	root, stateDir := wireFixture(t)
	bare := filepath.Join(t.TempDir(), "up.git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, bare, "init", "-q", "--bare", "-b", "main")
	repo := filepath.Join(root, "clean-pushed")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "add", "-A")
	wireGit(t, repo, "commit", "-q", "-m", "one")
	wireGit(t, repo, "remote", "add", "origin", bare)
	wireGit(t, repo, "push", "-q", "origin", "main")
	ageTree(t, repo, 30*24*time.Hour)

	var out bytes.Buffer
	if code := cmdDiscard([]string{"--yes", repo}, &out, os.Stderr, os.Stdin); code != ExitUsage {
		t.Fatalf("discard of SAFE dir must exit 120 (refusal, nothing deleted), got %d", code)
	}
	if _, err := os.Stat(repo); err != nil {
		t.Fatal("SAFE dir was deleted by discard")
	}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	var sawSkip bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var row struct {
			Event   string `json:"event"`
			SkipWhy string `json:"skipWhy"`
			OK      *bool  `json:"ok"`
		}
		if json.Unmarshal([]byte(line), &row) == nil && row.Event == "skip" && row.SkipWhy == applycmd.SkipVerdictChanged {
			sawSkip = true
			if row.OK == nil || *row.OK {
				t.Fatal("skip line must carry ok=false")
			}
		}
	}
	if !sawSkip {
		t.Fatal("ledger missing the verdict-changed skip line")
	}
}

// Non-interactive discard without --yes is 121 and touches nothing; the
// --no-quarantine non-TTY combination is a USAGE error (120): the flag
// demands an interactive confirm that cannot even be asked.
func TestWiringDiscardNonTTYNeedsYes(t *testing.T) {
	root, _ := wireFixture(t)
	repo := filepath.Join(root, "d")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if code := cmdDiscard([]string{repo}, &bytes.Buffer{}, os.Stderr, os.Stdin); code != applycmd.ExitNotTTY {
		t.Fatalf("non-TTY without --yes: %d (want 121)", code)
	}
	if _, err := os.Stat(repo); err != nil {
		t.Fatal("dir touched by a 121 refusal")
	}
	if code := cmdDiscard([]string{"--no-quarantine", "--yes", repo}, &bytes.Buffer{}, os.Stderr, os.Stdin); code != ExitUsage {
		t.Fatalf("--no-quarantine non-TTY: %d (want 120)", code)
	}
}

// A non-git scratch-idle dir (SAFE) also refuses: discard never widens.
func TestWiringDiscardRefusesScratch(t *testing.T) {
	root, _ := wireFixture(t)
	target := filepath.Join(root, "scratch-old")
	var out bytes.Buffer
	if code := cmdDiscard([]string{"--yes", target}, &out, os.Stderr, os.Stdin); code != ExitUsage {
		t.Fatalf("scratch discard: %d (want 120)", code)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("SAFE scratch dir was deleted by discard")
	}
}

// A held dirty dir is KEEP and survives discard: holds beat every rule and
// every flag, even --yes (the round-1 panel's held-dir major).
func TestWiringDiscardHeldSurvives(t *testing.T) {
	root, _ := wireFixture(t)
	repo := filepath.Join(root, "held-dirty")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "add", "-A")
	wireGit(t, repo, "commit", "-q", "-m", "one")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, repo, 30*24*time.Hour)
	if code := cmdHold([]string{"--for", "720h", repo}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold: %d", code)
	}
	if code := cmdDiscard([]string{"--yes", repo}, &bytes.Buffer{}, os.Stderr, os.Stdin); code != ExitUsage {
		t.Fatalf("held dirty discard: %d (want 120)", code)
	}
	if _, err := os.Stat(repo); err != nil {
		t.Fatal("held dir was deleted by discard")
	}
}

// Over-cap quarantine refuses with the dir untouched and exit 125, with the
// snapshot-overcap skipWhy (the closed enum's cap member).
func TestWiringDiscardOverCap125(t *testing.T) {
	root, stateDir := wireFixture(t)
	repo := filepath.Join(root, "fat")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "add", "-A")
	wireGit(t, repo, "commit", "-q", "-m", "one")
	// ~4 MB of INCOMPRESSIBLE untracked content (zeros or short-period
	// patterns pack to nothing and slip under the cap): the bundle
	// exceeds a 1 MB cap.
	big := make([]byte, 4<<20)
	if _, err := crand.Read(big); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, repo, 30*24*time.Hour)
	// Custom config: a 1 MB quarantine cap.
	cfg := `{
  "roots": ["` + filepath.ToSlash(root) + `"],
  "protect": [],
  "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21, "remote-stale-hours": 72, "quarantine-cap-gb": 0.001, "quarantine-retention-days": 30, "quarantine-margin": 2.5, "min-free-mb": 256, "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"},
  "gh": false,
  "jj": true
}`
	if err := os.WriteFile(filepath.Join(stateDir, "config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REAP_DIR", stateDir)

	var out bytes.Buffer
	if code := cmdDiscard([]string{"--yes", repo}, &out, os.Stderr, os.Stdin); code != applycmd.ExitQuarantine {
		t.Fatalf("over-cap discard: %d (want 125)", code)
	}
	if _, err := os.Stat(repo); err != nil {
		t.Fatal("over-cap discard deleted the dir")
	}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if !strings.Contains(string(raw), `"skipWhy":"snapshot-overcap"`) {
		t.Fatalf("ledger missing snapshot-overcap skip:\n%s", raw)
	}
}

// Duplicate PATH args dedupe to one deletion (no phantom 'missing' skip
// forcing exit 2), and the summary prints the two-number truth.
func TestWiringDiscardDedupeAndTwoNumber(t *testing.T) {
	root, _ := wireFixture(t)
	repo := filepath.Join(root, "dup")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "add", "-A")
	wireGit(t, repo, "commit", "-q", "-m", "one")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, repo, 30*24*time.Hour)

	var out bytes.Buffer
	if code := cmdDiscard([]string{"--yes", repo, repo}, &out, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("deduped discard: %d (%s)", code, out.String())
	}
	if _, err := os.Stat(repo); !os.IsNotExist(err) {
		t.Fatal("dir survived")
	}
	if !strings.Contains(out.String(), "freed") || !strings.Contains(out.String(), "bundle") || !strings.Contains(out.String(), "kept") {
		t.Fatalf("two-number truth missing: %q", out.String())
	}
}

// reap log lists across the rotation boundary, oldest-first.
func TestWiringLogAcrossRotation(t *testing.T) {
	_, stateDir := wireFixture(t)
	oldTS := time.Now().Add(-96 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := os.WriteFile(filepath.Join(stateDir, "reap.log.1"),
		[]byte(`{"ts":"`+oldTS+`","event":"intent","path":"C:\\rot-old"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	freshTS := time.Now().UTC().Format(time.RFC3339Nano)
	if err := os.WriteFile(filepath.Join(stateDir, "reap.log"),
		[]byte(`{"ts":"`+freshTS+`","event":"result","path":"C:\\rot-new","ok":true}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cmdLog(nil, &out, os.Stderr); code != ExitOK {
		t.Fatalf("log: %d", code)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("rotation listing: %q", out.String())
	}
	if !strings.Contains(lines[0], "rot-old") || !strings.Contains(lines[1], "rot-new") {
		t.Fatalf("rotation order wrong: %q", out.String())
	}
}

// restore: the first-class recovery command, end to end — bundle sessions
// materialize the capture tree; a non-empty --to destination is refused.
func TestWiringQuarantineRestore(t *testing.T) {
	root, stateDir := wireFixture(t)
	repo := filepath.Join(root, "gone")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "add", "-A")
	wireGit(t, repo, "commit", "-q", "-m", "one")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("PRECIOUS"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, repo, 30*24*time.Hour)
	if code := cmdDiscard([]string{"--yes", repo}, &bytes.Buffer{}, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatal("discard failed")
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, "quarantine"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("sessions: %v", err)
	}
	session := entries[0].Name()

	dest := filepath.Join(t.TempDir(), "recovered")
	var out bytes.Buffer
	if code := cmdQuarantine([]string{"restore", session, "--to", dest}, &out, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("restore: %d (%s)", code, out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "f.txt")); string(b) != "PRECIOUS" {
		t.Fatal("restore did not materialize the captured tree")
	}
	// Non-empty destination: refused, nothing overwritten.
	if err := os.WriteFile(filepath.Join(dest, "existing.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdQuarantine([]string{"restore", session, "--to", dest}, &out, os.Stderr, os.Stdin); code != ExitUsage {
		t.Fatalf("restore to non-empty: %d (want 120)", code)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "existing.txt")); string(b) != "x" {
		t.Fatal("restore overwrote the destination")
	}
}

// Delta restore survives ROUTINE REMOTE ADVANCEMENT: the remote's tips
// moving past the recorded base is not a gone base — restore fetches the
// remote and verifies the prerequisite object exists (round-3 fix of the
// ls-remote-tips false refusal).
func TestWiringRestoreRemoteAdvanced(t *testing.T) {
	base := t.TempDir()
	bare := filepath.Join(base, "up.git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, bare, "init", "-q", "--bare", "-b", "main")
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("pushed"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "add", "-A")
	wireGit(t, repo, "commit", "-q", "-m", "one")
	wireGit(t, repo, "remote", "add", "origin", bare)
	wireGit(t, repo, "push", "-q", "-u", "origin", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("DIRTY-DELTA"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, repo, 30*24*time.Hour)

	// State dir rooted at base so the discard fixture is cheap; the repo is
	// outside scan roots, discard takes explicit paths.
	stateDir := filepath.Join(base, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeWireConfig(t, stateDir, base)
	if code := cmdDiscard([]string{"--yes", repo}, &bytes.Buffer{}, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("discard: %d", code)
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, "quarantine"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("sessions: %v", err)
	}

	// Advance the remote one commit past the recorded base.
	adv := filepath.Join(base, "adv")
	wireGit(t, base, "clone", "-q", bare, adv)
	if err := os.WriteFile(filepath.Join(adv, "new.txt"), []byte("advanced"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, adv, "add", "-A")
	wireGit(t, adv, "commit", "-q", "-m", "advance")
	wireGit(t, adv, "push", "-q", "origin", "main")

	dest := filepath.Join(base, "recovered")
	var out bytes.Buffer
	if code := cmdQuarantine([]string{"restore", entries[0].Name(), "--to", dest}, &out, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("restore after remote advanced: %d (%s)", code, out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "f.txt")); string(b) != "DIRTY-DELTA" {
		t.Fatal("advanced-remote delta did not restore")
	}
}

// Empty dirs survive a bundle discard + restore cycle (the manifest records
// them relative; restore recreates them under the destination).
func TestWiringRestoreEmptyDirs(t *testing.T) {
	root, stateDir := wireFixture(t)
	repo := filepath.Join(root, "empty-holder")
	if err := os.MkdirAll(filepath.Join(repo, "keepme"), 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "add", "-A")
	wireGit(t, repo, "commit", "-q", "-m", "one")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, repo, 30*24*time.Hour)
	if code := cmdDiscard([]string{"--yes", repo}, &bytes.Buffer{}, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("discard: %d", code)
	}
	entries, _ := os.ReadDir(filepath.Join(stateDir, "quarantine"))
	if len(entries) != 1 {
		t.Fatalf("sessions: %d", len(entries))
	}
	dest := filepath.Join(t.TempDir(), "rec")
	if code := cmdQuarantine([]string{"restore", entries[0].Name(), "--to", dest}, &bytes.Buffer{}, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatal("restore failed")
	}
	if fi, err := os.Stat(filepath.Join(dest, "keepme")); err != nil || !fi.IsDir() {
		t.Fatal("empty dir not recreated by restore")
	}
}

// prune --json reports failures with the SAME exit band as text (125), not
// a machine-readable success on partial destruction failure.
func TestWiringPruneJSONFailure125(t *testing.T) {
	_, stateDir := wireFixture(t)
	s := quarantine.SessionDir(stateDir, `C:\x\held`, time.Now().Add(-48*time.Hour))
	if err := os.MkdirAll(filepath.Join(s, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(s, "sub", "locked.bin")
	if err := os.WriteFile(victim, []byte("held"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour)
	os.Chtimes(s, old, old)

	// Hold the file open WITHOUT delete-sharing: RemoveAll cannot remove it.
	held, herr := holdNoDelete(t, victim)
	if herr != nil {
		t.Skipf("cannot hold file: %v", herr)
	}
	defer held.Close()

	var out bytes.Buffer
	code := cmdQuarantine([]string{"prune", "--older-than", "24h", "--yes", "--json"}, &out, os.Stderr, os.Stdin)
	if code != applycmd.ExitQuarantine {
		t.Fatalf("prune --json with a failed bundle: %d (want 125), out=%s", code, out.String())
	}
	if !strings.Contains(out.String(), `"failed":1`) {
		t.Fatalf("json body must report the failure: %s", out.String())
	}
}

// plan --exclude stashes: 'stashes' is a code the verdict engine itself
// emits, so the closed enum must accept it (round-3 spec finding).
func TestWiringPlanExcludeStashes(t *testing.T) {
	_, _ = wireFixture(t)
	if code := cmdPlan([]string{"--no-gh", "--exclude", "stashes"}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("plan --exclude stashes: %d", code)
	}
}

// quarantine list/prune through the command layer, including the
// recovery-ends-here copy and the young-session survival.
func TestWiringQuarantineLifecycle(t *testing.T) {
	_, stateDir := wireFixture(t)
	old := quarantine.SessionDir(stateDir, `C:\x\old`, time.Now().Add(-48*time.Hour))
	young := quarantine.SessionDir(stateDir, `C:\x\young`, time.Now())
	for _, s := range []string{old, young} {
		if err := os.MkdirAll(s, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(old, "manifest.json"), []byte(`{"mode":"bundle","source":"C:\\x\\old"}`), 0o644)
	os.WriteFile(filepath.Join(young, "manifest.json"), []byte(`{"mode":"plain-copy","source":"C:\\x\\young"}`), 0o644)
	back := time.Now().Add(-72 * time.Hour)
	os.Chtimes(old, back, back)

	var out bytes.Buffer
	if code := cmdQuarantine([]string{"list"}, &out, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("list: %d", code)
	}
	if !strings.Contains(out.String(), "old") || !strings.Contains(out.String(), "state=verified-ok") || !strings.Contains(out.String(), "restore: reap quarantine restore") {
		t.Fatalf("list output: %q", out.String())
	}

	out.Reset()
	if code := cmdQuarantine([]string{"prune", "--older-than", "24h", "--yes"}, &out, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("prune: %d", code)
	}
	if !strings.Contains(out.String(), "recovery") || !strings.Contains(out.String(), "pruned 1 session(s)") {
		t.Fatalf("prune output: %q", out.String())
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old session survived prune")
	}
	if _, err := os.Stat(young); err != nil {
		t.Fatal("young session was pruned")
	}
}

// log --since filters both the human rows and the raw JSONL.
func TestWiringLogSince(t *testing.T) {
	_, stateDir := wireFixture(t)
	oldTS := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	freshTS := time.Now().UTC().Format(time.RFC3339Nano)
	body := `{"ts":"` + oldTS + `","event":"intent","path":"C:\\old"}` + "\n" +
		`{"ts":"` + freshTS + `","event":"result","path":"C:\\new","ok":true}` + "\n"
	if err := os.WriteFile(filepath.Join(stateDir, "reap.log"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var text, raw bytes.Buffer
	if code := cmdLog([]string{"--since", "24h"}, &text, os.Stderr); code != ExitOK {
		t.Fatalf("log text: %d", code)
	}
	if strings.Contains(text.String(), "old") || !strings.Contains(text.String(), "new") {
		t.Fatalf("text --since filter: %q", text.String())
	}
	if code := cmdLog([]string{"--json", "--since", "24h"}, &raw, os.Stderr); code != ExitOK {
		t.Fatalf("log json: %d", code)
	}
	jsonLines := strings.Split(strings.TrimSpace(raw.String()), "\n")
	if len(jsonLines) != 1 || !strings.Contains(jsonLines[0], `"result"`) {
		t.Fatalf("json --since filter: %q", raw.String())
	}
}

// doctor smoke: exit 0, state readout, free lock, and stray healing through
// the command layer.
func TestWiringDoctorSmoke(t *testing.T) {
	root, _ := wireFixture(t)
	stray := filepath.Join(root, "strayed.reap-probing")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stray, "keep.txt"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cmdDoctor(nil, &out, os.Stderr); code != ExitOK {
		t.Fatalf("doctor: %d (%s)", code, out.String())
	}
	for _, want := range []string{"state dir:", "apply.lock: free", "quarantine:", "reap.log:", "gh:", "jj:", "stray"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("doctor missing %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "strayed", "keep.txt")); err != nil {
		t.Fatal("stray .reap-probing dir was not healed back")
	}
}
