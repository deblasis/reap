package cli

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deblasis/reap/internal/applycmd"
	"github.com/deblasis/reap/internal/auditlog"
	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/ghx"
	"github.com/deblasis/reap/internal/incodalog"
	"github.com/deblasis/reap/internal/jjx"
	"github.com/deblasis/reap/internal/lockfile"
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
	// HERMETIC (round 6; the R5 gate-red): the destructive suite must
	// never read the machine's LIVE incoda rail - a real torn ticket or
	// lane transition mid-suite reds unrelated tests through the sentinel
	// (live-demonstrated by two seats independently). A fresh empty
	// INCODA_DIR = no rail. Tests that deliberately build rail fixtures
	// setenv their own AFTER this (the later Setenv wins).
	t.Setenv("INCODA_DIR", filepath.Join(t.TempDir(), "no-rail"))
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
	// via the real writer  -  hand-built JSON with raw Windows backslashes is
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
	// The INTENT line's manifest decodes to real entries (round 11: the
	// write-ahead recovery story, not just the result's post-hoc record).
	if im, ok := intent["manifest"].(string); ok && im != "" {
		dec, derr := base64.StdEncoding.DecodeString(im)
		if derr != nil || !strings.Contains(string(dec), "junk1.bin") {
			t.Fatalf("intent manifest missing real entries: %v %q", derr, dec)
		}
	} else {
		t.Fatal("intent line missing its write-ahead manifest")
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
	// Round 6 band: the not-BLOCKED refusal fires per-path AFTER the ledger
	// opens (skip record + envelope) - the run executed-with-skips, so the
	// band and the record agree at 2.
	if code := cmdDiscard([]string{"--yes", repo}, &out, os.Stderr, os.Stdin); code != applycmd.ExitWithSkips {
		t.Fatalf("discard of SAFE dir must exit 2 (refusal recorded, nothing deleted), got %d", code)
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
	if code := cmdDiscard([]string{"--yes", target}, &out, os.Stderr, os.Stdin); code != applycmd.ExitWithSkips {
		t.Fatalf("scratch discard: %d (want 2; the per-path refusal is a recorded skip)", code)
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
	// Wave-0 rail: the held dir refuses BEFORE the ledger opens (nothing
	// executed, nothing recorded) - the 120 band and the empty record
	// agree. Post-ledger refusals are the ones that land in 2.
	if code := cmdDiscard([]string{"--yes", repo}, &bytes.Buffer{}, os.Stderr, os.Stdin); code != ExitUsage {
		t.Fatalf("held dirty discard: %d (want 120; wave-0, pre-ledger)", code)
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

// restore: the first-class recovery command, end to end  -  bundle sessions
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
// moving past the recorded base is not a gone base  -  restore fetches the
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

// THE WIDENING GATE (round-6 spec major, live-proven by the R5 panel):
// --include/--override-manual must refuse IGNORANCE rows at resolution
// time  -  a remote-stale dir may not widen into the plan, and the refusal
// carries the side-door copy. The re-verify backstop was never enough: no
// output may advertise a gate the tool will refuse.
func TestWiringWideningGateRefusesIgnorance(t *testing.T) {
	root, _ := wireFixture(t)
	repo := filepath.Join(root, "stale-remote")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "add", "-A")
	wireGit(t, repo, "commit", "-q", "-m", "one")
	bare := filepath.Join(t.TempDir(), "up.git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, bare, "init", "-q", "--bare", "-b", "main")
	wireGit(t, repo, "remote", "add", "origin", bare)
	wireGit(t, repo, "push", "-q", "origin", "main")
	// No FETCH_HEAD marker after aging => remote-stale (an ignorance row).
	ageTree(t, repo, 30*24*time.Hour)

	var out, errOut bytes.Buffer
	if code := cmdPlan([]string{"--no-gh", "--include", "remote-stale"}, &out, &errOut); code != ExitUsage {
		t.Fatalf("plan --include remote-stale must refuse at resolution (120), got %d: %s %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String()+errOut.String(), "side door") {
		t.Fatalf("refusal copy must carry the side-door sentence: %s %s", out.String(), errOut.String())
	}
	errOut.Reset()
	if code := cmdApply([]string{"--no-gh", "--yes", "--override-manual", repo}, &bytes.Buffer{}, &errOut, os.Stdin); code != ExitUsage {
		t.Fatalf("apply --override-manual on a remote-stale dir must refuse at resolution (120), got %d", code)
	}
	if _, err := os.Stat(repo); err != nil {
		t.Fatal("remote-stale dir was deleted")
	}
}

// The spec-listed --override-manual refusal trio (L658-661), pinned two
// rounds late: KEEP (held) and BLOCKED-class-shadowed refuse at 120 naming
// the row and the shadowed fact, in plan AND apply (ignorance was already
// pinned). A regression deleting the refusal pass must fail here.
func TestWiringOverrideRefusalTrio(t *testing.T) {
	root, _ := wireFixture(t)

	// KEEP: hold a scratch dir, then --override-manual it.
	held := filepath.Join(root, "held")
	if err := os.MkdirAll(held, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(held, "x.bin"), make([]byte, 3000), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-40 * 24 * time.Hour)
	filepath.WalkDir(held, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			os.Chtimes(p, past, past)
		}
		return nil
	})
	if code := cmdHold([]string{"--for", "168h", held}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold: %d", code)
	}
	var e2 bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes", "--override-manual", held}, &bytes.Buffer{}, &e2, os.Stdin); code != ExitUsage {
		t.Fatalf("apply override held: %d (want 120)", code)
	}
	if !strings.Contains(e2.String(), "not override-eligible") {
		t.Fatalf("held refusal copy: %q", e2.String())
	}

	// BLOCKED-class-shadowed: a dirty repo (BLOCKED dirty-files) given as
	// --override-manual must refuse naming the shadowed fact, not widen.
	dirty := filepath.Join(root, "dirtyrepo")
	if err := os.MkdirAll(dirty, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, dirty, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dirty, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, dirty, "add", "-A")
	wireGit(t, dirty, "commit", "-q", "-m", "one")
	if err := os.WriteFile(filepath.Join(dirty, "f.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, dirty, 30*24*time.Hour)
	var e3 bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes", "--override-manual", dirty}, &bytes.Buffer{}, &e3, os.Stdin); code != ExitUsage {
		t.Fatalf("apply override dirty: %d (want 120)", code)
	}
	if !strings.Contains(e3.String(), "not override-eligible") || !strings.Contains(e3.String(), "shadowed fact") {
		t.Fatalf("shadowed refusal copy: %q", e3.String())
	}
	if _, err := os.Stat(dirty); err != nil {
		t.Fatal("dirty dir deleted by an override refusal")
	}
}

// The forget-then-rm crash window, pinned end to end through ALL surfaces
// (round 10: round 9's re-route was scan-display-only  -  the shared plan
// pipeline refused the row its own hint advertised). A forgotten workspace
// must verdict orphaned-workspace in scan AND plan, and delete through the
// TTY carve-out.
func TestWiringDeregisteredWorkspaceCarveOut(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj not on PATH")
	}
	base, err := os.MkdirTemp("", "jj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	root := filepath.Join(base, "root")
	stateDir := filepath.Join(base, "state")
	for _, d := range []string{root, stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeWireConfig(t, stateDir, root)
	parent := filepath.Join(root, "parent")
	if out, err := exec.Command("jj", "git", "init", "--colocate", parent).CombinedOutput(); err != nil {
		t.Skipf("jj git init --colocate: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(parent, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("jj", "-R", parent, "commit", "-m", "one").CombinedOutput(); err != nil {
		t.Skipf("jj commit: %v\n%s", err, out)
	}

	ws := filepath.Join(root, "forgotten-ws")
	if out, err := exec.Command("jj", "-R", parent, "workspace", "add", ws).CombinedOutput(); err != nil {
		t.Skipf("jj workspace add: %v\n%s", err, out)
	}
	// Deregister: the crash shape.
	if out, err := exec.Command("jj", "-R", parent, "workspace", "forget", "forgotten-ws").CombinedOutput(); err != nil {
		t.Skipf("jj workspace forget: %v\n%s", err, out)
	}
	ageTree(t, ws, 30*24*time.Hour)

	// Scan: the row must be orphaned-workspace (not facts-unavailable).
	var scanOut bytes.Buffer
	if code := cmdScan([]string{"--no-gh", "--json"}, &scanOut, os.Stderr); code != ExitOK {
		t.Fatalf("scan: %d", code)
	}
	if !strings.Contains(scanOut.String(), "orphaned-workspace") {
		t.Fatalf("deregistered ws not routed to orphaned-workspace in scan:\n%s", scanOut.String())
	}

	// TTY apply through the carve-out: the hint must be executable.
	restore := applycmd.ForceTerminal(true)
	defer restore()
	if code := cmdApply([]string{"--no-gh", "--override-manual", ws}, os.Stdout, os.Stderr, answerStdin(t, "y\ny\n")); code != ExitOK {
		t.Fatalf("TTY carve-out on the deregistered ws: %d", code)
	}
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		t.Fatal("deregistered ws survived the carve-out")
	}
}

func answerStdin(t *testing.T, answers string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ans")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if _, err := f.WriteString(answers); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	return f
}

// discard on an IGNORANCE row (locked index = state-unreadable): the
// refusal carries the fix-the-tool remedy, never the plan/--override-manual
// pointers that would refuse it too (round 11's pin of the round-10 fold).
func TestWiringDiscardIgnoranceRemedy(t *testing.T) {
	root, _ := wireFixture(t)
	repo := filepath.Join(root, "locked")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	wireGit(t, repo, "commit", "-q", "--allow-empty", "-m", "one")
	if err := os.WriteFile(filepath.Join(repo, ".git", "index.lock"), []byte("held"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, repo, 30*24*time.Hour)
	var e bytes.Buffer
	if code := cmdDiscard([]string{"--yes", repo}, &bytes.Buffer{}, &e, os.Stdin); code != applycmd.ExitWithSkips {
		t.Fatalf("locked-index discard: %d (want 2; the run executed with a skip record)", code)
	}
	// The contract is NO DEAD GATES on ignorance rows: neither the
	// plan/--override-manual pointers nor a false remedy may appear (the
	// two honest shapes are the unreadable-state retry and the
	// fix-the-tool remedy).
	if strings.Contains(e.String(), "--include") || strings.Contains(e.String(), "--override-manual") {
		t.Fatalf("dead-gate pointers advertised on an ignorance row: %q", e.String())
	}
	if !strings.Contains(e.String(), "fix the tool") && !strings.Contains(e.String(), "unreadable") {
		t.Fatalf("ignorance remedy copy missing: %q", e.String())
	}
}

// The scan/plan/apply AGREEMENT harness (spec L512-513, '(tested)'):
// over one mixed fixture tree, the SAFE set scan reports equals the plan's
// dir set - guarding the hand-synced pipelines against the drift class
// that born the round-9 major.
func TestWiringScanPlanAgreement(t *testing.T) {
	root, _ := wireFixture(t)
	// A clean-pushed repo beside the scratch dir: two shapes, one tree.
	repo := filepath.Join(root, "pushed")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, repo, "add", "-A")
	wireGit(t, repo, "commit", "-q", "-m", "one")
	bare := filepath.Join(t.TempDir(), "up.git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, bare, "init", "-q", "--bare", "-b", "main")
	wireGit(t, repo, "remote", "add", "origin", bare)
	wireGit(t, repo, "push", "-q", "origin", "main")
	ageTree(t, repo, 30*24*time.Hour)

	var scanOut bytes.Buffer
	if code := cmdScan([]string{"--no-gh", "--json"}, &scanOut, os.Stderr); code != ExitOK {
		t.Fatalf("scan: %d", code)
	}
	var rep struct {
		Entries []struct {
			Path    string `json:"path"`
			Verdict string `json:"verdict"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(scanOut.Bytes(), &rep); err != nil {
		t.Fatalf("scan json: %v", err)
	}
	safeSet := map[string]bool{}
	for _, e := range rep.Entries {
		if e.Verdict == "SAFE" {
			safeSet[filepath.Clean(e.Path)] = true
		}
	}
	var planOut bytes.Buffer
	if code := cmdPlan([]string{"--no-gh"}, &planOut, os.Stderr); code != ExitOK {
		t.Fatalf("plan: %d", code)
	}
	if len(safeSet) == 0 {
		t.Fatal("fixture produced no SAFE rows")
	}
	for p := range safeSet {
		if !strings.Contains(planOut.String(), p) {
			t.Fatalf("SAFE dir %s missing from plan (scan/plan disagree):\n%s", p, planOut.String())
		}
	}
	// And nothing in the plan is outside the SAFE set (the default plan
	// widens nothing).
	for _, line := range strings.Split(planOut.String(), "\n") {
		if strings.Contains(line, "GB  ") && !strings.Contains(line, "dry-run") {
			found := false
			for p := range safeSet {
				if strings.Contains(line, p) {
					found = true
					break
				}
			}
			if !found && strings.TrimSpace(line) != "" {
				t.Fatalf("plan lists a non-SAFE dir by default:\n%s", line)
			}
		}
	}
}

// The mid-run floor stop, driven through the FreeBytes seam (round 12; the
// seam was built in round 9 and never exercised). One orphan: the plain
// copy succeeds, the mid-run recheck trips, the dir STANDS with its
// session kept and a skip line on the ledger, exit 125.
func TestWiringCarveOutFloorStop(t *testing.T) {
	restore := applycmd.ForceTerminal(true)
	defer restore()
	base, err := os.MkdirTemp("", "jj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	root := filepath.Join(base, "root")
	stateDir := filepath.Join(base, "state")
	for _, d := range []string{root, stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeWireConfig(t, stateDir, root)
	ph := filepath.Join(base, "ph")
	if out, err := exec.Command("git", "init", "-q", "-b", "main", ph).CombinedOutput(); err != nil {
		t.Skipf("git init: %v %s", err, out)
	}
	wt := filepath.Join(root, "orph")
	if out, err := exec.Command("git", "-C", ph, "worktree", "add", "-q", wt).CombinedOutput(); err != nil {
		t.Skipf("worktree add: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(wt, "only.txt"), []byte("PRECIOUS"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(ph)
	ageTree(t, wt, 30*24*time.Hour)

	// FreeBytes drops below the floor after the preflight reads (Confirm's
	// floor + freeBefore pass; the mid-run recheck after the plain copy
	// trips).
	orig := auditlog.FreeBytes
	calls := 0
	auditlog.FreeBytes = func(path string) uint64 {
		calls++
		if calls <= 2 {
			return orig(path)
		}
		return 1 << 20 // 1 MB: below every floor
	}
	t.Cleanup(func() { auditlog.FreeBytes = orig })

	if code := cmdApply([]string{"--no-gh", "--override-manual", wt}, os.Stdout, os.Stderr, answerStdin(t, "y\ny\n")); code != applycmd.ExitQuarantine {
		t.Fatalf("floor-stop run: %d (want 125)", code)
	}
	// The dir stands with its session kept on disk and on the ledger.
	if _, serr := os.Stat(wt); serr != nil {
		t.Fatal("floor-stopped orphan was deleted")
	}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if !strings.Contains(string(raw), "free space below floor") {
		t.Fatalf("floor-stop skip line missing:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"quarantinePath":"`) {
		t.Fatalf("skip line must carry the kept session's pointer:\n%s", raw)
	}
	sessions, _ := os.ReadDir(filepath.Join(stateDir, "quarantine"))
	if len(sessions) != 1 {
		t.Fatalf("kept session: %d", len(sessions))
	}
}

// The round-13 pins: the held-deregistered row keeps a NON-BLANK reason
// carrying the shadowed fact (keep() now carries BlockedClassFact), and
// the counts compose identically at the prompt and the intent line.
func TestWiringHeldDeregisteredReason(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj not on PATH")
	}
	base, err := os.MkdirTemp("", "jj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	root := filepath.Join(base, "root")
	stateDir := filepath.Join(base, "state")
	for _, d := range []string{root, stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeWireConfig(t, stateDir, root)
	parent := filepath.Join(root, "p")
	if out, err := exec.Command("jj", "git", "init", "--colocate", parent).CombinedOutput(); err != nil {
		t.Skipf("jj git init --colocate: %v\n%s", err, out)
	}
	ws := filepath.Join(root, "w")
	if out, err := exec.Command("jj", "-R", parent, "workspace", "add", ws).CombinedOutput(); err != nil {
		t.Skipf("jj workspace add: %v\n%s", err, out)
	}
	if out, err := exec.Command("jj", "-R", parent, "workspace", "forget", "w").CombinedOutput(); err != nil {
		t.Skipf("jj workspace forget: %v\n%s", err, out)
	}
	ageTree(t, ws, 30*24*time.Hour)
	if code := cmdHold([]string{"--for", "168h", ws}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold: %d", code)
	}
	// The held row: KEEP with the rail's reason AND the shadowed fact.
	var scanOut bytes.Buffer
	if code := cmdScan([]string{"--no-gh", "--json"}, &scanOut, os.Stderr); code != ExitOK {
		t.Fatalf("scan: %d", code)
	}
	if !strings.Contains(scanOut.String(), `"verdict": "KEEP"`) {
		t.Fatalf("held deregistered ws not KEEP:\n%s", scanOut.String())
	}
	if strings.Contains(scanOut.String(), `"reason": ""`) {
		t.Fatalf("blank reason regression on a held deregistered row:\n%s", scanOut.String())
	}
}

// The prompt-vs-ledger COUNTS EQUALITY (round 14 pin; the round-13 fix
// was live-proven by the panel but unshipped as a test): a broken-branch
// orphan driven through the TTY carve-out must record the SAME counts
// text at the hardened confirm and on the intent line.
func TestWiringCarveOutCountsEquality(t *testing.T) {
	restore := applycmd.ForceTerminal(true)
	defer restore()
	base, err := os.MkdirTemp("", "jj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	root := filepath.Join(base, "root")
	stateDir := filepath.Join(base, "state")
	for _, d := range []string{root, stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeWireConfig(t, stateDir, root)
	ph := filepath.Join(base, "ph")
	if out, err := exec.Command("git", "init", "-q", "-b", "main", ph).CombinedOutput(); err != nil {
		t.Skipf("git init: %v %s", err, out)
	}
	wt := filepath.Join(root, "orph")
	if out, err := exec.Command("git", "-C", ph, "worktree", "add", "-q", wt).CombinedOutput(); err != nil {
		t.Skipf("worktree add: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(wt, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", wt, "add", "-A").CombinedOutput(); err != nil {
		t.Skipf("git add: %v %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(wt, "f.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, "u.txt"), []byte("u"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(ph)
	ageTree(t, wt, 30*24*time.Hour)

	// Capture the confirm prompt: stdout to a file (the TTY check requires
	// an *os.File).
	promptPath := filepath.Join(t.TempDir(), "prompt.txt")
	pf, err := os.Create(promptPath)
	if err != nil {
		t.Fatal(err)
	}
	if code := cmdApply([]string{"--no-gh", "--override-manual", wt}, pf, os.Stderr, answerStdin(t, "y\ny\n")); code != ExitOK {
		t.Fatalf("TTY carve-out: %d", code)
	}
	pf.Close()
	prompt, _ := os.ReadFile(promptPath)
	raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))

	// The counts text at the prompt equals the counts text on the intent
	// line (the one-voice invariant).
	line := ""
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.Contains(l, `"event":"intent"`) && strings.Contains(l, "hardened confirm shown") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("intent line with counts missing:\n%s", raw)
	}
	start := strings.Index(line, "counts: ")
	j := strings.Index(line[start+8:], ");")
	if start < 0 || j < 0 {
		t.Fatalf("cannot extract counts from intent line:\n%s", line)
	}
	intentCounts := line[start+8 : start+8+j]
	if !strings.Contains(string(prompt), intentCounts) {
		t.Fatalf("prompt/ledger counts divergence: prompt lacks %q\nprompt:\n%s", intentCounts, prompt)
	}
}

// The (also:) suffix on an ORDINARY held KEEP row (round 14: the gate was
// carve-out-only, leaving held/protected rows bare against the spec's
// unqualified L467-468). A held DIRTY repo must render 'held by user
// (also: N dirty/untracked files)'.
func TestWiringHeldDirtyRepoCarriesAlso(t *testing.T) {
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
	if code := cmdHold([]string{"--for", "168h", repo}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold: %d", code)
	}
	var scanOut bytes.Buffer
	if code := cmdScan([]string{"--no-gh", "--json"}, &scanOut, os.Stderr); code != ExitOK {
		t.Fatalf("scan: %d", code)
	}
	if !strings.Contains(scanOut.String(), "held by user (also: ") {
		t.Fatalf("(also:) suffix missing on the held KEEP row:\n%s", scanOut.String())
	}
	if !strings.Contains(scanOut.String(), "dirty/untracked files") {
		t.Fatalf("the shadowed fact text missing:\n%s", scanOut.String())
	}
}

// The mid-run incoda re-probe, PINNED at BOTH deletion paths (round 4; the
// round-3 discard half printed the refusal and deleted anyway - live-caught
// by the panel): a ticket taken during the confirm window leaves the dir
// standing, at apply AND at discard.
func TestWiringConfirmWindowTicketSurvival(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "root")
	stateDir := filepath.Join(d, "state")
	for _, p := range []string{root, stateDir, filepath.Join(d, "queues", "q")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeWireConfig(t, stateDir, root)
	t.Setenv("INCODA_DIR", d)

	// A dirty repo to discard.
	repo := filepath.Join(root, "wip")
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

	// A held ticket naming the repo (the mid-run job).
	ticket := filepath.Join(d, "queues", "q", "1-2.ticket")
	body := fmt.Sprintf(`{"pid":1,"queue":"q","cwd":%q}`, repo)
	if err := os.WriteFile(ticket, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := lockfileOpenForTestCli(ticket)
	if err != nil {
		t.Skipf("open ticket: %v", err)
	}
	held, terr := f.TryLock()
	if err != nil || !held {
		t.Fatalf("hold: %v", terr)
	}
	defer f.Close()

	// Discard: the dir must SURVIVE (round 3 deleted it after the refusal).
	// Round 6: the all-refused-after-confirm run lands in the 2
	// executed-with-skips band - the ledger already records an executed run
	// (skip line + envelope); the band and the record now agree.
	var dOut bytes.Buffer
	if code := cmdDiscard([]string{"--yes", repo}, &dOut, os.Stderr, os.Stdin); code != applycmd.ExitWithSkips {
		t.Fatalf("discard under a live ticket: %d (want 2) (%s)", code, dOut.String())
	}
	if _, serr := os.Stat(repo); serr != nil {
		t.Fatal("discard DELETED the dir under a live ticket (the round-3 bug back)")
	}

	// Apply: a ticket naming the SCAN ROW's dir (scratch-old) is caught at
	// scan time — the row verdicts ACTIVE/incoda-live and never plans. (The
	// under-lock abort covers the scan-to-lock window, which a pre-created
	// ticket cannot exercise deterministically: the scan already caught it.)
	ticket2 := filepath.Join(d, "queues", "q", "3-4.ticket")
	body2 := fmt.Sprintf(`{"pid":3,"queue":"q","cwd":%q}`, filepath.Join(root, "scratch-old"))
	if err := os.WriteFile(ticket2, []byte(body2), 0o644); err != nil {
		t.Fatal(err)
	}
	f2, err2 := lockfileOpenForTestCli(ticket2)
	if err2 != nil {
		t.Skipf("open ticket2: %v", err2)
	}
	held2, terr2 := f2.TryLock()
	if err2 != nil || !held2 {
		t.Fatalf("hold2: %v", terr2)
	}
	defer f2.Close()
	var js bytes.Buffer
	if code := cmdScan([]string{"--no-gh", "--json"}, &js, os.Stderr); code != ExitOK {
		t.Fatalf("scan under a live root ticket: %d", code)
	}
	if !strings.Contains(js.String(), "incoda-live") {
		t.Fatalf("scan does not mark the live-ticket dir incoda-live:\n%s", js.String())
	}
	// And apply with nothing plannable deletes nothing (exit 0, 0 planned).
	var aOut bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes"}, &aOut, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("apply under a live ticket at the root: %d (%s)", code, aOut.String())
	}
	if _, serr := os.Stat(repo); serr != nil {
		t.Fatal("apply deleted the live-ticket dir")
	}
}

// lastIncoda end-to-end (round 4 pin, repaired round 5): a natural-casing
// dir= record joins (the canonicalization), the exact mock-worded form
// renders (owner, compact ago, %q reason - the fixture timestamp is
// NOW-RELATIVE so the '2h' clause is reachable, not dead weight), the
// null-owner and no-record forms render, and scan --json carries the
// field with owner present-but-empty when no owner= was written (a null
// owner and an absent field are different facts).
func TestWiringLastIncodaEndToEnd(t *testing.T) {
	d := t.TempDir()
	root := t.TempDir()
	stateDir := filepath.Join(d, "state")
	qd := filepath.Join(d, "queues", "q")
	for _, p := range []string{stateDir, qd, filepath.Join(root, "no-owner"), filepath.Join(root, "no-record")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeWireConfig(t, stateDir, root)
	t.Setenv("INCODA_DIR", d)

	// The with-record dir in NATURAL casing (the canonicalization probe:
	// the raw key must join the canonical lookup).
	withDir := filepath.Join(root, "With-Record")
	if err := os.MkdirAll(withDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04:05")
	log := fmt.Sprintf("%s queue=q event=release pid=1 dir=%s reason=\"probe run\" owner=agent dur=1h\n", ts, withDir) +
		fmt.Sprintf("%s queue=q event=release pid=2 dir=%s reason=\"nightly\" dur=1h\n", ts, filepath.Join(root, "no-owner"))
	if err := os.WriteFile(filepath.Join(qd, "lane.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}

	var text bytes.Buffer
	if code := cmdScan([]string{"--no-gh"}, &text, os.Stderr); code != ExitOK {
		t.Fatalf("scan: %d", code)
	}
	if !strings.Contains(text.String(), `last: agent, 2h, "probe run"`) {
		t.Fatalf("with-record 'last:' exact form missing:\n%s", text.String())
	}
	if !strings.Contains(text.String(), `last: -, 2h, "nightly"`) {
		t.Fatalf("null-owner 'last:' form missing:\n%s", text.String())
	}
	if !strings.Contains(text.String(), "last: no incoda record") {
		t.Fatalf("no-record form missing:\n%s", text.String())
	}

	var js bytes.Buffer
	if code := cmdScan([]string{"--no-gh", "--json"}, &js, os.Stderr); code != ExitOK {
		t.Fatalf("scan --json: %d", code)
	}
	var rep struct {
		Entries []struct {
			Path       string `json:"path"`
			LastIncoda *struct {
				Ago    string `json:"ago"`
				Owner  string `json:"owner"`
				Reason string `json:"reason"`
			} `json:"lastIncoda"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(js.Bytes(), &rep); err != nil {
		t.Fatalf("scan json: %v", err)
	}
	sawOwner, sawNullOwner, sawNone := false, false, false
	for _, e := range rep.Entries {
		switch {
		case strings.EqualFold(filepath.Clean(e.Path), filepath.Clean(withDir)):
			if e.LastIncoda == nil || e.LastIncoda.Owner != "agent" || e.LastIncoda.Reason != "probe run" || e.LastIncoda.Ago != "2h" {
				t.Fatalf("with-record lastIncoda: %+v", e.LastIncoda)
			}
			sawOwner = true
		case strings.HasSuffix(filepath.Clean(e.Path), "no-owner"):
			if e.LastIncoda == nil {
				t.Fatal("no-owner row lost its lastIncoda entirely (omitempty erasure)")
			}
			if e.LastIncoda.Owner != "" || e.LastIncoda.Ago != "2h" {
				t.Fatalf("no-owner lastIncoda: %+v", e.LastIncoda)
			}
			sawNullOwner = true
		case strings.HasSuffix(filepath.Clean(e.Path), "no-record"):
			if e.LastIncoda != nil {
				t.Fatalf("no-record row carries a record: %+v", e.LastIncoda)
			}
			sawNone = true
		}
	}
	if !sawOwner || !sawNullOwner || !sawNone {
		t.Fatalf("rows not all found: owner=%v nullOwner=%v none=%v\n%s", sawOwner, sawNullOwner, sawNone, js.String())
	}
	// The RAW key must be present with an empty value: a struct decode
	// cannot distinguish present-but-empty from omitted (the omitempty
	// erasure the schema must never do).
	if !strings.Contains(js.String(), `"owner": ""`) {
		t.Fatalf("null owner serialized absent (omitempty erasure):\n%s", js.String())
	}
}

// The ACTIVE-rail LOG triggers, pinned at the scan level (round 5; the
// spec's named fixture half 'enqueued-not-released WITHOUT a live ticket'
// had zero coverage - deleting both trigger lines failed no test): an OPEN
// record within active-hours flips an otherwise-SAFE aged scratch dir to
// ACTIVE/incoda-live; the same record beyond the window does not.
func TestWiringIncodaLogTriggersActive(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "root")
	stateDir := filepath.Join(d, "state")
	qd := filepath.Join(d, "queues", "q")
	for _, p := range []string{root, stateDir, qd, filepath.Join(root, "recent-open"), filepath.Join(root, "stale-open")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"recent-open", "stale-open"} {
		if err := os.WriteFile(filepath.Join(root, n, "x.bin"), make([]byte, 3000), 0o644); err != nil {
			t.Fatal(err)
		}
		ageTree(t, filepath.Join(root, n), 30*24*time.Hour)
	}
	writeWireConfig(t, stateDir, root)
	t.Setenv("INCODA_DIR", d)

	// OPEN acquires (no terminator, no ticket anywhere): one 10m ago, one
	// 72h ago (beyond the 48h active-hours window).
	recent := time.Now().Add(-10 * time.Minute).Format("2006-01-02 15:04:05")
	stale := time.Now().Add(-72 * time.Hour).Format("2006-01-02 15:04:05")
	log := fmt.Sprintf("%s queue=q event=acquire pid=1 dir=%s\n", recent, filepath.Join(root, "recent-open")) +
		fmt.Sprintf("%s queue=q event=acquire pid=2 dir=%s\n", stale, filepath.Join(root, "stale-open"))
	if err := os.WriteFile(filepath.Join(qd, "lane.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}

	var js bytes.Buffer
	if code := cmdScan([]string{"--no-gh", "--json"}, &js, os.Stderr); code != ExitOK {
		t.Fatalf("scan: %d", code)
	}
	var rep struct {
		Entries []struct {
			Path       string `json:"path"`
			Verdict    string `json:"verdict"`
			ReasonCode string `json:"reasonCode"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(js.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	row := func(suffix string) *struct {
		Path       string `json:"path"`
		Verdict    string `json:"verdict"`
		ReasonCode string `json:"reasonCode"`
	} {
		for i := range rep.Entries {
			if strings.HasSuffix(filepath.Clean(rep.Entries[i].Path), suffix) {
				return &rep.Entries[i]
			}
		}
		return nil
	}
	r := row("recent-open")
	if r == nil {
		t.Fatalf("recent-open row missing:\n%s", js.String())
	}
	if r.Verdict != "ACTIVE" || r.ReasonCode != "incoda-live" {
		t.Fatalf("open-record-within-window not ACTIVE/incoda-live: %+v", r)
	}
	s := row("stale-open")
	if s == nil {
		t.Fatalf("stale-open row missing:\n%s", js.String())
	}
	if s.ReasonCode == "incoda-live" {
		t.Fatalf("open record beyond the window fired the rail: %+v", s)
	}
}

// The apply under-lock gate abort, TRACED and pinned (round 5; the branch
// had zero coverage and previously returned with no ledger line at all):
// a ticket the confirm-window re-probe sees aborts the whole run at 122
// naming the dir, nothing deletes, and the ledger carries the abort result
// line plus the envelope (planned N, deleted 0, skipped N - the aborted
// run's reconciled truth).
func TestWiringApplyGateAbortTraced(t *testing.T) {
	root, stateDir := wireFixture(t)
	target := filepath.Join(root, "scratch-old")
	restore := func() { confirmReprobeLive = defaultConfirmReprobeLive }
	confirmReprobeLive = func(activeHours time.Duration) map[string]bool {
		return map[string]bool{config.Canonical(target): true}
	}
	defer restore()

	var e bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes"}, &bytes.Buffer{}, &e, os.Stdin); code != ExitState {
		t.Fatalf("gate abort: %d (want 122): %s", code, e.String())
	}
	if !strings.Contains(e.String(), "run aborted, nothing deleted") {
		t.Fatalf("abort copy missing: %q", e.String())
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("gate-aborted run deleted the dir")
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if err != nil {
		t.Fatal(err)
	}
	// The pin names the EVENT: a reverted result ok=false line (which reap
	// log renders 'FAILED') would satisfy every other assertion here.
	if !strings.Contains(string(raw), `"event":"abort"`) {
		t.Fatalf("ledger missing the explicit abort line:\n%s", raw)
	}
	if strings.Contains(string(raw), `"event":"result"`) {
		t.Fatalf("an aborted run must record no deletion result lines:\n%s", raw)
	}
	if !strings.Contains(string(raw), "run aborted, nothing deleted") {
		t.Fatalf("ledger abort line missing the cause:\n%s", raw)
	}
	var envelope map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) == nil && row["event"] == "envelope" {
			envelope = row
		}
	}
	if envelope == nil {
		t.Fatal("gate-abort run wrote no envelope")
	}
	// Zero counts are omitempty in the ledger schema: absent means 0.
	if d, ok := envelope["deleted"].(float64); ok && d != 0 {
		t.Fatalf("gate-abort envelope deleted: %v", d)
	}
	if envelope["skipped"].(float64) == 0 {
		t.Fatalf("gate-abort envelope must count every planned path skipped: %v", envelope)
	}
}

// The discard confirm-window refusal in a MIXED batch (round 5; the R4
// refusal vanished from the ledger and --json and the run exited 0): the
// refused path becomes a skip record, the envelope's planned counts what
// the prompt advertised, the sibling still deletes, exit 2.
func TestWiringDiscardMixedRunTicketRefusalSkips(t *testing.T) {
	root, stateDir := wireFixture(t)
	a := filepath.Join(root, "wip-a")
	b := filepath.Join(root, "wip-b")
	for _, repo := range []string{a, b} {
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
	}
	confirmReprobeLive = func(activeHours time.Duration) map[string]bool {
		return map[string]bool{config.Canonical(a): true}
	}
	t.Cleanup(func() { confirmReprobeLive = defaultConfirmReprobeLive })

	var out, e bytes.Buffer
	if code := cmdDiscard([]string{"--yes", a, b}, &out, &e, os.Stdin); code != applycmd.ExitWithSkips {
		t.Fatalf("mixed refusal run: %d (want 2): %s / %s", code, out.String(), e.String())
	}
	if _, err := os.Stat(a); err != nil {
		t.Fatal("refused dir was deleted")
	}
	if _, err := os.Stat(b); !os.IsNotExist(err) {
		t.Fatal("sibling did not delete")
	}
	if !strings.Contains(e.String(), "the dir is NOT discarded") {
		t.Fatalf("refusal copy missing: %q", e.String())
	}
	if !strings.Contains(out.String(), "skipped "+a) {
		t.Fatalf("summary missing the refused skip: %q", out.String())
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"skipWhy":"verdict-changed"`) {
		t.Fatalf("ledger missing the refusal skip line:\n%s", raw)
	}
	var envelope map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var row map[string]any
		if json.Unmarshal([]byte(line), &row) == nil && row["event"] == "envelope" {
			envelope = row
		}
	}
	if envelope == nil || envelope["planned"].(float64) != 2 || envelope["deleted"].(float64) != 1 || envelope["skipped"].(float64) != 1 {
		t.Fatalf("mixed-run envelope must reconcile planned=2/deleted=1/skipped=1: %v", envelope)
	}
}

// The per-path pre-deletion re-sweep (round 5): a ticket that lands AFTER
// the confirm-window probe (injected at the sweep seam - the window is not
// fixture-reachable) skips the path with the session kept, the sibling
// still deletes, exit 2.
func TestWiringPerPathTicketSweepSkips(t *testing.T) {
	root, stateDir := wireFixture(t)
	a := filepath.Join(root, "sweep-a")
	b := filepath.Join(root, "sweep-b")
	for _, repo := range []string{a, b} {
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
	}
	perPathTicketHit = func(path string) (bool, bool) { return path == a, false }
	t.Cleanup(func() { perPathTicketHit = incodalog.LiveTicketHit })

	var out, e bytes.Buffer
	if code := cmdDiscard([]string{"--yes", a, b}, &out, &e, os.Stdin); code != applycmd.ExitWithSkips {
		t.Fatalf("per-path sweep run: %d (want 2): %s / %s", code, out.String(), e.String())
	}
	if _, err := os.Stat(a); err != nil {
		t.Fatal("mid-run-ticketed dir was deleted")
	}
	if _, err := os.Stat(b); !os.IsNotExist(err) {
		t.Fatal("sibling did not delete")
	}
	if !strings.Contains(e.String(), "re-swept immediately before deletion") {
		t.Fatalf("re-sweep copy missing: %q", e.String())
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if err != nil {
		t.Fatal(err)
	}
	sawQPtr := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var row struct {
			Event      string  `json:"event"`
			Path       string  `json:"path"`
			SkipWhy    string  `json:"skipWhy"`
			Quarantine *string `json:"quarantinePath"`
		}
		if json.Unmarshal([]byte(line), &row) == nil && row.Event == "skip" && strings.HasSuffix(filepath.ToSlash(row.Path), "sweep-a") {
			if row.SkipWhy != "verdict-changed" {
				t.Fatalf("sweep skip why: %q", row.SkipWhy)
			}
			// The session taken for the skipped path is KEPT and pointed at.
			if row.Quarantine != nil && *row.Quarantine != "" {
				sawQPtr = true
			}
		}
	}
	if !sawQPtr {
		t.Fatalf("sweep skip line carries no session pointer:\n%s", raw)
	}
}

// The doctor incoda readout (round 5 pins): the candidate-dir dir=
// attribution share, and the UNKNOWN-LIVE rail line naming the failure
// counts when a held ticket's body yields no dir.
func TestWiringDoctorIncodaLines(t *testing.T) {
	d := t.TempDir()
	root := t.TempDir()
	stateDir := filepath.Join(d, "state")
	qd := filepath.Join(d, "queues", "q")
	for _, p := range []string{stateDir, qd, filepath.Join(root, "attributed"), filepath.Join(root, "bare")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeWireConfig(t, stateDir, root)
	t.Setenv("INCODA_DIR", d)

	ts := time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04:05")
	log := fmt.Sprintf("%s queue=q event=release pid=1 dir=%s reason=\"d\" owner=o dur=1h\n", ts, filepath.Join(root, "attributed"))
	if err := os.WriteFile(filepath.Join(qd, "lane.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	// A held ticket whose body parses to nothing: the rail must announce
	// unknown-live, not enumerate as complete.
	ticket := filepath.Join(qd, "9-9.ticket")
	if err := os.WriteFile(ticket, []byte("torn"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := lockfileOpenForTestCli(ticket)
	if err != nil {
		t.Skipf("open ticket: %v", err)
	}
	held, terr := f.TryLock()
	if err != nil || !held {
		t.Fatalf("hold: %v", terr)
	}
	defer f.Close()

	var out bytes.Buffer
	if code := cmdDoctor(nil, &out, os.Stderr); code != ExitOK {
		t.Fatalf("doctor: %d (%s)", code, out.String())
	}
	// scan NAMES the rail in its own output when the sentinel empties the
	// verdicts (round 7; not only in doctor).
	var e bytes.Buffer
	if code := cmdScan([]string{"--no-gh"}, &bytes.Buffer{}, &e); code != ExitOK {
		t.Fatalf("scan under the sentinel: %d", code)
	}
	if !strings.Contains(e.String(), "incoda rail UNKNOWN-LIVE") {
		t.Fatalf("scan must name the unknown rail: %q", e.String())
	}
	if !strings.Contains(out.String(), "dir= attribution 1/2 candidate dir(s)") {
		t.Fatalf("attribution share line wrong:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "incoda rail: UNKNOWN-LIVE") ||
		!strings.Contains(out.String(), "held ticket(s) without a readable dir") {
		t.Fatalf("unknown-live rail line missing:\n%s", out.String())
	}
}

// Overlapping roots, the ordering half (round 6; the R5 reliability
// major, live-proven: a parent candidate deleted FIRST destroyed the
// inner-root children, each recorded as a skip): roots=[X, X/mass] plan
// the parent AND the inner children in one run; path-nesting ordering
// deletes children first, the parent last, and NOTHING lands as a
// missing-skip.
func TestWiringOverlappingRootsChildrenFirst(t *testing.T) {
	d := t.TempDir()
	x := filepath.Join(d, "X")
	stateDir := filepath.Join(d, "state")
	inner := filepath.Join(x, "mass")
	for _, p := range []string{stateDir, inner, filepath.Join(inner, "m1"), filepath.Join(inner, "m2"), filepath.Join(x, "solo")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(inner, "m1", "x.bin"), filepath.Join(inner, "m2", "x.bin"), filepath.Join(x, "solo", "x.bin")} {
		if err := os.WriteFile(f, make([]byte, 3000), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-40 * 24 * time.Hour)
	filepath.WalkDir(d, func(p string, en os.DirEntry, err error) error {
		if err == nil {
			os.Chtimes(p, past, past)
		}
		return nil
	})
	writeWireConfig(t, stateDir, x)
	// The overlapping second root: X/mass is BOTH a root and a candidate
	// row under X.
	cfg := `{
  "roots": ["` + filepath.ToSlash(x) + `", "` + filepath.ToSlash(inner) + `"],
  "protect": [],
  "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21, "remote-stale-hours": 72, "quarantine-cap-gb": 2, "quarantine-retention-days": 30, "quarantine-margin": 2.5, "min-free-mb": 256, "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"},
  "gh": false,
  "jj": true
}`
	if err := os.WriteFile(filepath.Join(stateDir, "config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes"}, &out, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("overlapping-roots apply: %d (%s)", code, out.String())
	}
	for _, p := range []string{filepath.Join(inner, "m1"), filepath.Join(inner, "m2"), inner, filepath.Join(x, "solo")} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s survived (children must delete first, the parent last)", p)
		}
	}
	// X itself is a configured ROOT: rows are root children, and a root is
	// never a deletion candidate of its own scan.
	if _, err := os.Stat(x); err != nil {
		t.Fatalf("the outer root X was deleted: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if strings.Contains(string(raw), `"event":"skip"`) {
		t.Fatalf("a children-first run must leave no skips:\n%s", raw)
	}
	results := strings.Count(string(raw), `"event":"result"`)
	if results < 4 { // m1, m2, mass, solo
		t.Fatalf("expected the full deletion set on the ledger, saw %d results:\n%s", results, raw)
	}
}

// Overlapping roots, the HOLD half (round 6; the live-proven invariant
// break: 'holds beat every rule and every flag' destroyed by the parent's
// deletion, the run reporting 'skipped 0'): a hold on the inner dir stops
// the parent's deletion too - the containment direction anyHoldUnder never
// checked.
func TestWiringOverlappingRootsHoldSurvives(t *testing.T) {
	d := t.TempDir()
	x := filepath.Join(d, "X")
	stateDir := filepath.Join(d, "state")
	inner := filepath.Join(x, "mass")
	for _, p := range []string{stateDir, filepath.Join(inner, "m1"), filepath.Join(x, "solo")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(inner, "m1", "x.bin"), filepath.Join(x, "solo", "x.bin")} {
		if err := os.WriteFile(f, make([]byte, 3000), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-40 * 24 * time.Hour)
	filepath.WalkDir(d, func(p string, en os.DirEntry, err error) error {
		if err == nil {
			os.Chtimes(p, past, past)
		}
		return nil
	})
	writeWireConfig(t, stateDir, x)
	if code := cmdHold([]string{"--for", "720h", filepath.Join(inner, "m1")}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold: %d", code)
	}

	var e bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes"}, &bytes.Buffer{}, &e, os.Stdin); code != applycmd.ExitWithSkips {
		t.Fatalf("held-inner apply: %d (want 2): %s", code, e.String())
	}
	// THE invariant: the held dir STANDS (the parent's deletion must not
	// destroy it), and so does the parent (skipped as parent-of-live).
	if _, err := os.Stat(filepath.Join(inner, "m1")); err != nil {
		t.Fatal("a user hold was destroyed by the parent candidate's deletion")
	}
	if _, err := os.Stat(inner); err != nil {
		t.Fatal("the held dir's parent was deleted (the hold's protection must extend upward)")
	}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if !strings.Contains(string(raw), `"skipWhy":"parent-of-live-children"`) {
		t.Fatalf("parent skip line missing:\n%s", raw)
	}
	if !strings.Contains(e.String(), "held dir at/under it") {
		t.Fatalf("hold-under refusal copy missing: %q", e.String())
	}
}

// The unknown-rail copy carries its CAUSE (round 6; the R5 reliability
// finding: the refusal named 'a job landed' when the truth was 'the rail
// could not enumerate' - the operator's remedy differs).
func TestWiringUnknownRailCopy(t *testing.T) {
	root, _ := wireFixture(t)
	target := filepath.Join(root, "scratch-old")
	perPathTicketHit = func(path string) (bool, bool) { return true, true }
	t.Cleanup(func() { perPathTicketHit = incodalog.LiveTicketHit })
	var e bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes"}, &bytes.Buffer{}, &e, os.Stdin); code != applycmd.ExitWithSkips {
		t.Fatalf("unknown-rail apply: %d (want 2): %s", code, e.String())
	}
	if !strings.Contains(e.String(), "incoda rail UNKNOWN-LIVE") {
		t.Fatalf("unknown-rail copy must name the rail, not a job: %q", e.String())
	}
	if strings.Contains(e.String(), "a job landed") {
		t.Fatalf("unknown-rail copy lies about the cause: %q", e.String())
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("unknown-rail run deleted the dir")
	}
}

// reap never writes to incoda state (spec L540), pinned as a property: a
// scan+activity+doctor pass leaves the state dir byte-identical (the
// read-only surface; the destructive commands take apply.lock and touch
// no incoda path either - covered by the survival pins' fixtures).
func TestWiringIncodaStateUntouched(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "root")
	stateDir := filepath.Join(d, "state")
	qd := filepath.Join(d, "queues", "q")
	for _, p := range []string{root, stateDir, qd} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeWireConfig(t, stateDir, root)
	t.Setenv("INCODA_DIR", d)
	log := time.Now().Add(-2*time.Hour).Format("2006-01-02 15:04:05") +
		` queue=q event=release pid=1 dir=` + filepath.Join(root, "z") + ` reason="r" owner=o dur=1h` + "\n"
	if err := os.WriteFile(filepath.Join(qd, "lane.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(qd, "1-1.ticket"), []byte(`{"pid":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := func() string {
		var b strings.Builder
		filepath.WalkDir(d, func(p string, en os.DirEntry, err error) error {
			if en.IsDir() || strings.Contains(p, "state") {
				return nil // the REAP state dir legitimately mutates
			}
			h, _ := os.ReadFile(p)
			fmt.Fprintf(&b, "%s:%d:%q\n", p, len(h), h)
			return nil
		})
		return b.String()
	}
	before := sum()
	if code := cmdScan([]string{"--no-gh"}, &bytes.Buffer{}, os.Stderr); code != ExitOK {
		t.Fatalf("scan: %d", code)
	}
	if code := cmdActivity(nil, &bytes.Buffer{}, os.Stderr); code != ExitOK {
		t.Fatalf("activity: %d", code)
	}
	if code := cmdDoctor(nil, &bytes.Buffer{}, os.Stderr); code != ExitOK {
		t.Fatalf("doctor: %d", code)
	}
	if after := sum(); after != before {
		t.Fatalf("reap wrote to incoda state:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// The unpinned normative rules (round 6, the spec seat's list): activity
// takes no paths (120), doctor states the no-lane.log shape, and the
// DESCENDANT half of 'live ticket at/under dir' flips a scan row.
func TestWiringUnpinnedEdges(t *testing.T) {
	_, _ = wireFixture(t) // hermetic INCODA_DIR (no rail)
	if code := cmdActivity([]string{"some-path"}, &bytes.Buffer{}, os.Stderr); code != ExitUsage {
		t.Fatalf("activity positional arg: %d (want 120)", code)
	}
	var doc bytes.Buffer
	if code := cmdDoctor(nil, &doc, os.Stderr); code != ExitOK {
		t.Fatalf("doctor: %d", code)
	}
	if !strings.Contains(doc.String(), "no lane.log found (attribution off;") {
		t.Fatalf("doctor no-lane.log line missing:\n%s", doc.String())
	}
}

// The DESCENDANT half of the at/under containment at scan level (round 6):
// a held ticket naming a SUBDIR of a row flips the row ACTIVE/incoda-live
// (both existing scan-level pins name the row itself).
func TestWiringDescendantTicketFlipsRow(t *testing.T) {
	d := t.TempDir()
	root := filepath.Join(d, "root")
	stateDir := filepath.Join(d, "state")
	qd := filepath.Join(d, "queues", "q")
	row := filepath.Join(root, "parent-row")
	for _, p := range []string{stateDir, qd, row, filepath.Join(row, "child-work")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(row, "x.bin"), make([]byte, 3000), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, row, 30*24*time.Hour)
	writeWireConfig(t, stateDir, root)
	t.Setenv("INCODA_DIR", d)

	ticket := filepath.Join(qd, "5-5.ticket")
	body := fmt.Sprintf(`{"pid":5,"queue":"q","cwd":%q}`, filepath.Join(row, "child-work"))
	if err := os.WriteFile(ticket, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := lockfileOpenForTestCli(ticket)
	if err != nil {
		t.Skipf("open ticket: %v", err)
	}
	held, terr := f.TryLock()
	if err != nil || !held {
		t.Fatalf("hold: %v", terr)
	}
	defer f.Close()

	var js bytes.Buffer
	if code := cmdScan([]string{"--no-gh", "--json"}, &js, os.Stderr); code != ExitOK {
		t.Fatalf("scan: %d", code)
	}
	if !strings.Contains(js.String(), "incoda-live") {
		t.Fatalf("a live ticket under a subdir did not flip the parent row:\n%s", js.String())
	}
}

// The BOTH-CLEAN FAMILY UNLOCK, pinned for the GIT family via the flag no
// test had ever used (round 7; the R6 eng seat verified it live but zero
// pins existed): a clean-pushed parent with a live worktree child rows
// parent-of-live-children; --include parent-of-live-children deletes the
// child (SAFE) and unlocks the parent IN THE SAME RUN - the parent's
// re-verify must not trip on its own listing bump or the deregistration
// writes under .git.
func TestWiringBothCleanFamilyUnlockGit(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	stateDir := filepath.Join(base, "state")
	bare := filepath.Join(base, "up.git")
	for _, p := range []string{root, stateDir, bare} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeWireConfig(t, stateDir, root)
	wireGit(t, bare, "init", "-q", "--bare", "-b", "main")
	parent := filepath.Join(root, "p")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, parent, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(parent, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	wireGit(t, parent, "add", "-A")
	wireGit(t, parent, "commit", "-q", "-m", "one")
	wireGit(t, parent, "remote", "add", "origin", bare)
	wireGit(t, parent, "push", "-q", "origin", "main")
	// Fetch BEFORE aging (fetch refreshes refs too - a post-aging fetch
	// leaves fresh refs that row the parent ACTIVE), then age, then
	// backdate ONLY FETCH_HEAD: past the 48h activity floor, inside the
	// 72h remote window (a fully-aged tree rows remote-stale and the
	// child never plans).
	wireGit(t, parent, "fetch", "-q", "origin")
	wt := filepath.Join(root, "wt")
	if out, err := exec.Command("git", "-C", parent, "worktree", "add", "-q", wt).CombinedOutput(); err != nil {
		t.Skipf("worktree add: %v %s", err, out)
	}
	ageTree(t, parent, 30*24*time.Hour)
	ageTree(t, wt, 30*24*time.Hour)
	fresh := time.Now().Add(-60 * time.Hour)
	os.Chtimes(filepath.Join(parent, ".git", "FETCH_HEAD"), fresh, fresh)

	// The child worktree is a GIT row: reaching SAFE needs an AVAILABLE
	// PRHeads set (nil rows gh-unavailable). gh:true in the config, with
	// the fetchPRHeads seam injecting an empty available set - the same
	// shape a healthy join yields for repos with no GitHub remotes,
	// without the network flake.
	ghCfg := `{
  "roots": ["` + filepath.ToSlash(root) + `"],
  "protect": [],
  "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21, "remote-stale-hours": 72, "quarantine-cap-gb": 2, "quarantine-retention-days": 30, "quarantine-margin": 2.5, "min-free-mb": 256, "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"},
  "gh": true,
  "jj": true
}`
	if err := os.WriteFile(filepath.Join(stateDir, "config.json"), []byte(ghCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	restorePR := fetchPRHeads
	fetchPRHeads = func(budget time.Duration) ghx.PRHeads { return ghx.PRHeads{} }
	t.Cleanup(func() { fetchPRHeads = restorePR })
	var out bytes.Buffer
	if code := cmdApply([]string{"--yes", "--include", "parent-of-live-children"}, &out, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("both-clean git family unlock: %d (%s)", code, out.String())
	}
	if _, err := os.Stat(wt); !os.IsNotExist(err) {
		t.Fatal("the worktree child survived")
	}
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
		t.Fatalf("the parent did not unlock after its child deleted in-run\nOUT: %s\nLEDGER:\n%s", out.String(), raw)
	}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if strings.Contains(string(raw), `"event":"skip"`) {
		t.Fatalf("the one-run unlock must leave no skips:\n%s", raw)
	}
}

// The BOTH-CLEAN FAMILY UNLOCK for the JJ family (round 7; the R6 eng
// seat live-proved it DEAD: jj workspace forget writes fresh files into
// the parent's .jj, tripping the parent's own re-verify and stranding it
// ACTIVE for two days). With the deregistration-write exemption the
// parent unlocks in the same run.
func TestWiringBothCleanFamilyUnlockJJ(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj not on PATH")
	}
	base, err := os.MkdirTemp("", "jjunlock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	root := filepath.Join(base, "root")
	stateDir := filepath.Join(base, "state")
	for _, p := range []string{root, stateDir} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeWireConfig(t, stateDir, root)
	parent := filepath.Join(root, "p")
	if out, err := exec.Command("jj", "git", "init", "--colocate", parent).CombinedOutput(); err != nil {
		t.Skipf("jj git init --colocate: %v\n%s", err, out)
	}
	if err := os.WriteFile(filepath.Join(parent, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("jj", "-R", parent, "commit", "-m", "one").CombinedOutput(); err != nil {
		t.Skipf("jj commit: %v\n%s", err, out)
	}
	// Push the parent (a colocated repo exports to git): the family must
	// be clean+pushed for the unlock shape.
	bare := filepath.Join(base, "up.git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	wireGit(t, bare, "init", "-q", "--bare", "-b", "main")
	if out, err := exec.Command("jj", "-R", parent, "git", "remote", "add", "origin", bare).CombinedOutput(); err != nil {
		t.Skipf("jj git remote add: %v\n%s", err, out)
	}
	if out, err := exec.Command("jj", "-R", parent, "git", "push").CombinedOutput(); err != nil {
		t.Skipf("jj git push: %v\n%s", err, out)
	}
	ws := filepath.Join(root, "ws")
	if out, err := exec.Command("jj", "-R", parent, "workspace", "add", ws).CombinedOutput(); err != nil {
		t.Skipf("jj workspace add: %v\n%s", err, out)
	}
	// The workspace's own working-copy commit is a change of its own:
	// describe + push it too, or ws rows BLOCKED jj-unpushed and the
	// parent carries a shadowed unpushed fact (the family must be ALL
	// clean+pushed).
	if out, err := exec.Command("jj", "-R", ws, "describe", "-m", "ws head").CombinedOutput(); err != nil {
		t.Skipf("jj describe ws: %v\n%s", err, out)
	}
	if out, err := exec.Command("jj", "-R", ws, "git", "push", "--change", "@").CombinedOutput(); err != nil {
		t.Skipf("jj push ws change: %v\n%s", err, out)
	}
	ageTree(t, parent, 30*24*time.Hour)
	ageTree(t, ws, 30*24*time.Hour)
	// Fresh-enough remote marker, cold-enough tree (see the git family).
	if out, err := exec.Command("git", "-C", parent, "fetch", "-q", "origin").CombinedOutput(); err != nil {
		t.Skipf("git fetch: %v\n%s", err, out)
	}
	fresh := time.Now().Add(-60 * time.Hour)
	os.Chtimes(filepath.Join(parent, ".git", "FETCH_HEAD"), fresh, fresh)

	// gh:true + the fetchPRHeads seam (an empty AVAILABLE set): once the
	// child is gone the parent's fresh verdict falls through to the gh
	// join, and a nil PRHeads would row it gh-unavailable - the unlock
	// must land on clean-pushed (see the git family's note).
	ghCfg := `{
  "roots": ["` + filepath.ToSlash(root) + `"],
  "protect": [],
  "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21, "remote-stale-hours": 72, "quarantine-cap-gb": 2, "quarantine-retention-days": 30, "quarantine-margin": 2.5, "min-free-mb": 256, "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"},
  "gh": true,
  "jj": true
}`
	if err := os.WriteFile(filepath.Join(stateDir, "config.json"), []byte(ghCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	restorePR := fetchPRHeads
	fetchPRHeads = func(budget time.Duration) ghx.PRHeads { return ghx.PRHeads{} }
	t.Cleanup(func() { fetchPRHeads = restorePR })

	var out, eBuf bytes.Buffer
	if code := cmdApply([]string{"--yes", "--include", "parent-of-live-children"}, &out, &eBuf, os.Stdin); code != ExitOK {
		raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
		t.Fatalf("both-clean jj family unlock: %d (%s / %s)\nLEDGER:\n%s", code, out.String(), eBuf.String(), raw)
	}
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		t.Fatal("the workspace child survived")
	}
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Fatal("the parent did not unlock: the deregistration writes under .jj still trip its re-verify")
	}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if strings.Contains(string(raw), `"event":"skip"`) {
		t.Fatalf("the one-run unlock must leave no skips:\n%s", raw)
	}
}

func lockfileOpenForTestCli(path string) (*lockfile.File, error) {
	return lockfile.Open(path)
}

// The TTY carve-out choreography end to end through the ForceTerminal
// seam (round-6: ~80 lines of the tool's most dangerous surface had zero
// automated coverage because the terminal probe was untestable under
// `go test`). Answers flow through a real stdin file: confirm, hardened
// confirm, and (in the over-cap shape) the over-cap Proceed.
func TestWiringCarveOutTTYFlows(t *testing.T) {
	makeOrphan := func(t *testing.T) string {
		t.Helper()
		base := t.TempDir()
		ph := filepath.Join(base, "porph")
		if out, err := exec.Command("git", "init", "-q", "-b", "main", ph).CombinedOutput(); err != nil {
			t.Skipf("git init: %v %s", err, out)
		}
		wt := filepath.Join(base, "orphan-wt")
		if out, err := exec.Command("git", "-C", ph, "worktree", "add", "-q", wt).CombinedOutput(); err != nil {
			t.Skipf("worktree add: %v %s", err, out)
		}
		if err := os.WriteFile(filepath.Join(wt, "only-copy.txt"), []byte("PRECIOUS"), 0o644); err != nil {
			t.Fatal(err)
		}
		os.RemoveAll(ph)
		ageTree(t, wt, 30*24*time.Hour)
		return wt
	}
	answerFile := func(t *testing.T, answers string) *os.File {
		t.Helper()
		f, err := os.CreateTemp(t.TempDir(), "answers")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() }) // an open handle blocks Windows temp cleanup
		if _, err := f.WriteString(answers); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		return f
	}
	restore := applycmd.ForceTerminal(true)
	defer restore()

	// Accept-accept: the dir deletes with a plain-copy quarantine.
	wt := makeOrphan(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeWireConfig(t, stateDir, filepath.Dir(wt))
	if code := cmdApply([]string{"--no-gh", "--override-manual", wt}, os.Stdout, os.Stderr, answerFile(t, "y\ny\n")); code != ExitOK {
		t.Fatalf("TTY carve-out accept: %d", code)
	}
	if _, err := os.Stat(wt); !os.IsNotExist(err) {
		t.Fatal("carve-out dir survived both confirms")
	}
	sessions, _ := os.ReadDir(filepath.Join(stateDir, "quarantine"))
	if len(sessions) != 1 {
		t.Fatalf("carve-out plain-copy session: %d", len(sessions))
	}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "quarantine", sessions[0].Name(), "manifest.json"))
	if !strings.Contains(string(raw), "files only, no git objects") {
		t.Fatalf("plain-copy manifest label missing:\n%s", raw)
	}

	// Accept then decline at the hardened confirm: nothing happens.
	wt2 := makeOrphan(t)
	writeWireConfig(t, stateDir, filepath.Dir(wt2))
	if code := cmdApply([]string{"--no-gh", "--override-manual", wt2}, os.Stdout, os.Stderr, answerFile(t, "y\nn\n")); code != ExitOK {
		t.Fatalf("TTY carve-out decline: %d", code)
	}
	if _, err := os.Stat(wt2); err != nil {
		t.Fatal("dir deleted after a decline")
	}

	// The over-cap branch (tiny cap): accept-accept-accept deletes with
	// mode=plain-copy-skipped-overcap on the ledger; accept-accept-decline
	// skips with skipWhy=snapshot-overcap and exit 2 (dir intact).
	tinyCfg := func(stateDir, root string) {
		cfg := `{
  "roots": ["` + filepath.ToSlash(root) + `"],
  "protect": [],
  "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21, "remote-stale-hours": 72, "quarantine-cap-gb": 0.001, "quarantine-retention-days": 30, "quarantine-margin": 2.5, "min-free-mb": 8, "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"},
  "gh": false,
  "jj": true
}`
		if err := os.WriteFile(filepath.Join(stateDir, "config.json"), []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wt3 := makeOrphan(t)
	if err := os.WriteFile(filepath.Join(wt3, "bulk.bin"), make([]byte, 4<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, wt3, 30*24*time.Hour)
	tinyCfg(stateDir, filepath.Dir(wt3))
	// TTY-gated runs must pass an *os.File stdout: IsTerminal type-asserts
	// it (the seam forces the fd probe, but not the type check).
	if code := cmdApply([]string{"--no-gh", "--override-manual", wt3}, os.Stdout, os.Stderr, answerFile(t, "y\ny\ny\n")); code != ExitOK {
		t.Fatalf("TTY over-cap accept: %d", code)
	}
	// Never a silent absence, BOTH directions pinned: the accept carries
	// mode=plain-copy-skipped-overcap + the consent residue on the ledger,
	// and no quarantine session exists for it.
	accLedger, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if !strings.Contains(string(accLedger), `"mode":"plain-copy-skipped-overcap"`) {
		t.Fatalf("over-cap accept ledger mode missing:\n%s", accLedger)
	}
	if !strings.Contains(string(accLedger), "over-cap consent accepted") {
		t.Fatalf("over-cap consent intent line missing:\n%s", accLedger)
	}
	sessionsAfter, _ := os.ReadDir(filepath.Join(stateDir, "quarantine"))
	if len(sessionsAfter) > 1 { // the under-cap accept's one session only
		t.Fatalf("over-cap accept must not create a session: %d", len(sessionsAfter))
	}
	if _, err := os.Stat(wt3); !os.IsNotExist(err) {
		t.Fatal("over-cap-accepted dir survived three confirms")
	}
	wt4 := makeOrphan(t)
	if err := os.WriteFile(filepath.Join(wt4, "bulk.bin"), make([]byte, 4<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	ageTree(t, wt4, 30*24*time.Hour)
	tinyCfg(stateDir, filepath.Dir(wt4))
	if code := cmdApply([]string{"--no-gh", "--override-manual", wt4}, os.Stdout, os.Stderr, answerFile(t, "y\ny\nn\n")); code != applycmd.ExitWithSkips {
		t.Fatalf("TTY over-cap decline: %d (want 2)", code)
	}
	if _, err := os.Stat(wt4); err != nil {
		t.Fatal("over-cap-declined dir was deleted")
	}
	ledger, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if !strings.Contains(string(ledger), `"skipWhy":"snapshot-overcap"`) {
		t.Fatalf("decline skip line must carry snapshot-overcap:\n%s", ledger)
	}

	// --include can NEVER reach the carve-out (spec)  -  even on a TTY.
	wt5 := makeOrphan(t)
	writeWireConfig(t, stateDir, filepath.Dir(wt5))
	if code := cmdApply([]string{"--no-gh", "--include", "orphaned-worktree"}, os.Stdout, os.Stderr, answerFile(t, "y\ny\n")); code != ExitUsage {
		t.Fatalf("TTY --include orphaned-worktree must refuse (120), got %d", code)
	}
	if _, err := os.Stat(wt5); err != nil {
		t.Fatal("dir deleted via --include reach-through")
	}
}

// A LIVE split jj workspace classifies as jj-workspace with its parent
// resolved (round-6 engineering major: the .jj/repo pointer is relative to
// the .jj DIRECTORY; resolved against the workspace root every live parent
// read as gone).
func TestWiringSplitWorkspaceParentResolved(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj not on PATH")
	}
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if out, err := exec.Command("jj", "git", "init", "--colocate", parent).CombinedOutput(); err != nil {
		t.Skipf("jj git init --colocate: %v %s", err, out)
	}
	ws := filepath.Join(base, "ws")
	if out, err := exec.Command("jj", "-R", parent, "workspace", "add", ws).CombinedOutput(); err != nil {
		t.Skipf("jj workspace add: %v %s", err, out)
	}
	info := classify.Dir(ws)
	if info.Kind != classify.KindJJWorkspace {
		t.Fatalf("live workspace verdicts %s (want jj-workspace; the pointer mis-resolution is back)", info.Kind)
	}
	if info.ParentRepo == "" || !strings.Contains(strings.ToLower(info.ParentRepo), "parent") {
		t.Fatalf("parent not resolved: %+v", info)
	}
}

// The plain-copy restore round trip through the command layer (the
// carve-out's only recovery path had no test).
func TestWiringRestorePlainCopyRoundTrip(t *testing.T) {
	_, stateDir := wireFixture(t)
	src := filepath.Join(t.TempDir(), "originals")
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sub", "keep.bin"), []byte("PLAIN-COPY-ONLY"), 0o644); err != nil {
		t.Fatal(err)
	}
	session := quarantine.SessionDir(stateDir, src, time.Now())
	if _, err := quarantine.WritePlainCopy(session, src, 1<<20); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	var out bytes.Buffer
	if code := cmdQuarantine([]string{"restore", filepath.Base(session), "--to", dest}, &out, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("restore plain copy: %d (%s)", code, out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "sub", "keep.bin")); string(b) != "PLAIN-COPY-ONLY" {
		t.Fatal("plain-copy restore not byte-for-byte")
	}
	// Non-empty refusal in plain-copy mode too.
	if err := os.WriteFile(filepath.Join(dest, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := cmdQuarantine([]string{"restore", filepath.Base(session), "--to", dest}, &out, os.Stderr, os.Stdin); code != ExitUsage {
		t.Fatalf("plain-copy restore to non-empty: %d (want 120)", code)
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

// The op-identity GUARD pin (round 10; the R8/R9 board live-proved a
// genuine interposed op still deleted the parent): the capture seam
// injects the post-forget set PLUS a genuine-op name - the current set at
// reverify must differ and the arm must REFUSE (the parent skips
// verdict-changed and survives; the child still deletes).
func TestWiringInterposedOpRefusesGuard(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj not on PATH")
	}
	base, err := os.MkdirTemp("", "jjguard")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	root := filepath.Join(base, "root")
	stateDir := filepath.Join(base, "state")
	for _, p := range []string{root, stateDir} {
		os.MkdirAll(p, 0o755)
	}
	writeWireConfig(t, stateDir, root)
	parent := filepath.Join(root, "p")
	if out, err := exec.Command("jj", "git", "init", "--colocate", parent).CombinedOutput(); err != nil {
		t.Skipf("jj init: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(parent, "f.txt"), []byte("one"), 0o644)
	exec.Command("jj", "-R", parent, "commit", "-m", "one").CombinedOutput()
	bare := filepath.Join(base, "up.git")
	os.MkdirAll(bare, 0o755)
	wireGit(t, bare, "init", "-q", "--bare", "-b", "main")
	exec.Command("jj", "-R", parent, "git", "remote", "add", "origin", bare).CombinedOutput()
	exec.Command("jj", "-R", parent, "git", "push").CombinedOutput()
	ws := filepath.Join(root, "ws")
	exec.Command("jj", "-R", parent, "workspace", "add", ws).CombinedOutput()
	exec.Command("jj", "-R", ws, "describe", "-m", "ws head").CombinedOutput()
	exec.Command("jj", "-R", ws, "git", "push", "--change", "@").CombinedOutput()
	ageTree(t, parent, 30*24*time.Hour)
	ageTree(t, ws, 30*24*time.Hour)
	exec.Command("git", "-C", parent, "fetch", "-q", "origin").CombinedOutput()
	fresh := time.Now().Add(-60 * time.Hour)
	os.Chtimes(filepath.Join(parent, ".git", "FETCH_HEAD"), fresh, fresh)
	ghCfg := `{
  "roots": ["` + filepath.ToSlash(root) + `"],
  "protect": [],
  "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21, "remote-stale-hours": 72, "quarantine-cap-gb": 2, "quarantine-retention-days": 30, "quarantine-margin": 2.5, "min-free-mb": 256, "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"},
  "gh": true,
  "jj": true
}`
	os.WriteFile(filepath.Join(stateDir, "config.json"), []byte(ghCfg), 0o644)
	restorePR := fetchPRHeads
	fetchPRHeads = func(budget time.Duration) ghx.PRHeads { return ghx.PRHeads{} }
	t.Cleanup(func() { fetchPRHeads = restorePR })
	// The seam: the captured set carries ONE name the current set will not
	// have (a genuine op landed after the capture).
	restoreCap := captureOpHeads
	captureOpHeads = func(repo string) []string {
		return append(jjx.OpHeadNames(repo), "genuine-interposed-op")
	}
	t.Cleanup(func() { captureOpHeads = restoreCap })

	var out bytes.Buffer
	if code := cmdApply([]string{"--yes", "--include", "parent-of-live-children"}, &out, os.Stderr, os.Stdin); code != applycmd.ExitWithSkips {
		t.Fatalf("interposed-op run: %d (want 2; the guard must refuse the parent): %s", code, out.String())
	}
	if _, err := os.Stat(ws); !os.IsNotExist(err) {
		t.Fatal("the workspace child survived (the child must still delete)")
	}
	if _, err := os.Stat(parent); err != nil {
		t.Fatal("the parent was DELETED under a genuine interposed op (the vacuous guard is back)")
	}
	raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if !strings.Contains(string(raw), `"skipWhy":"verdict-changed"`) {
		t.Fatalf("the guard refusal must be a verdict-changed skip: %s", raw)
	}
}
