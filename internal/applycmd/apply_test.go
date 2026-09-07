package applycmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/gitx"
)

// Lineage: children (worktrees/workspaces whose parent is also in the set)
// delete BEFORE the parent, at ANY depth (the two-level version dropped
// grandchildren while still counting them planned).
func TestOrderChildrenFirstAnyDepth(t *testing.T) {
	plan := []PlanEntry{
		{Path: `C:\repo`, ParentRepo: `C:\repo`, Kind: string(classify.KindGitRepo)},
		{Path: `C:\mid`, ParentRepo: `C:\repo`, Kind: string(classify.KindGitWorktree)},
		{Path: `C:\grand`, ParentRepo: `C:\mid`, Kind: string(classify.KindGitWorktree)},
		{Path: `C:\unrelated`, ParentRepo: `C:\unrelated`, Kind: string(classify.KindScratch)},
	}
	ordered := OrderChildrenFirst(plan)
	if len(ordered) != 4 {
		t.Fatalf("grandchild dropped: %d of 4 emitted", len(ordered))
	}
	pos := map[string]int{}
	for i, p := range ordered {
		pos[p.Path] = i
	}
	if pos[`C:\grand`] > pos[`C:\mid`] || pos[`C:\mid`] > pos[`C:\repo`] {
		t.Fatalf("lineage order violated: %v", pathsOf(ordered))
	}
}

func pathsOf(plan []PlanEntry) []string {
	out := make([]string, len(plan))
	for i, p := range plan {
		out[i] = p.Path
	}
	return out
}

// The rename probe: a quiet dir probes and restores cleanly.
func TestRenameProbeQuiet(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cand")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := renameProbe(target); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cand.reap-probing")); !os.IsNotExist(err) {
		t.Fatal("probe leftover after restore")
	}
}

// Probe-strand healing: original absent -> rename back; both present ->
// parked as .reap-orphaned-<ts> (never overwritten).
func TestHealProbingStrays(t *testing.T) {
	dir := t.TempDir()
	stray := filepath.Join(dir, "a.reap-probing")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	HealProbingStrays(dir)
	if _, err := os.Stat(filepath.Join(dir, "a")); err != nil {
		t.Fatalf("original not healed: %v", err)
	}
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Fatal("stray still present after heal")
	}
	if err := os.MkdirAll(filepath.Join(dir, "a2"), 0o755); err != nil {
		t.Fatal(err)
	}
	stray2 := filepath.Join(dir, "a2.reap-probing")
	if err := os.MkdirAll(stray2, 0o755); err != nil {
		t.Fatal(err)
	}
	HealProbingStrays(dir)
	if _, err := os.Stat(filepath.Join(dir, "a2")); err != nil {
		t.Fatal("original must stay untouched")
	}
	parked := false
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "a2.reap-probing.reap-orphaned-") {
			parked = true
		}
	}
	if !parked {
		t.Fatal("stray must be parked as .reap-orphaned-<ts>")
	}
}

func TestDeleteRemovesEverything(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "cand")
	if err := os.MkdirAll(filepath.Join(target, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "sub", "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeContentsBeforeVCS(target); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(longPath(target)); !os.IsNotExist(err) {
		t.Fatal("target must be gone")
	}
}

// apply.lock: exclusive (second Lock fails fast, naming the holder).
func TestLockFailsFast(t *testing.T) {
	dir := t.TempDir()
	l1, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Close()
	_, err = Lock(dir)
	if err == nil {
		t.Fatal("second Lock must fail fast")
	}
	if !strings.Contains(err.Error(), "apply.lock") {
		t.Fatalf("error must name the lock: %v", err)
	}
}

// Holds round-trip: the round-1 blocker was a writer/reader shape mismatch
// that bricked every command after one hold. One shared shape now.
func TestHoldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	hf := map[string]time.Time{`c:\temp\keepme`: time.Now().Add(48 * time.Hour)}
	if err := WriteHolds(dir, hf); err != nil {
		t.Fatal(err)
	}
	back := ReadHoldsSnapshot(dir)
	if len(back) != 1 {
		t.Fatalf("round trip lost holds: %+v", back)
	}
	if _, ok := back[`c:\temp\keepme`]; !ok {
		t.Fatalf("canonical key mismatch: %+v", back)
	}
}

// The re-verify tripwire: a fresh dir skips as active-tripwire.
func TestReverifyTripwireSkipsFreshDir(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	target := filepath.Join(root, "cand")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	rv := Reverify(target, "scratch-idle", false, cfg, Deleter{}, config.ExpandRoots(cfg.Protect), nil, nil)
	if rv.SkipWhy != SkipActiveTripwire || rv.Verdict.Verdict != "ACTIVE" {
		t.Fatalf("fresh dir: skip=%q verdict=%s", rv.SkipWhy, rv.Verdict.Verdict)
	}
}

// Protected paths never pass re-verify (KEEP beats every rule and flag).
func TestReverifyProtectedSkips(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "cand")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(target, old, old); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	protected := []string{"**/cand/**"}
	rv := Reverify(target, "scratch-idle", false, cfg, Deleter{}, protected, nil, nil)
	if rv.SkipWhy != SkipVerdictChanged || rv.Verdict.Verdict != "KEEP" {
		t.Fatalf("protected dir: skip=%q verdict=%s", rv.SkipWhy, rv.Verdict.Verdict)
	}
}

// A scratch-idle-planned dir whose fresh verdict drifted to a DIFFERENT
// judgment code skips as verdict-changed (the round-1 blocker: any
// judgment MANUAL fell through to deletion).
func TestReverifyFreshCodeMustMatchPlan(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "cand")
	if err := os.MkdirAll(filepath.Join(target, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Nested VCS marker routes the fresh verdict nested-repositories; the
	// plan said scratch-idle.
	if err := os.MkdirAll(filepath.Join(target, "vendor", "x", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	_ = os.Chtimes(target, old, old)
	cfg := config.Default()
	rv := Reverify(target, "scratch-idle", false, cfg, Deleter{}, config.ExpandRoots(cfg.Protect), nil, nil)
	if rv.SkipWhy != SkipVerdictChanged {
		t.Fatalf("drifted code: skip=%q verdict=%s/%s (must skip verdict-changed)", rv.SkipWhy, rv.Verdict.Verdict, rv.Verdict.Code)
	}
}

// Confirm: the free-space floor REFUSES (round-1: print-only), non-TTY
// without --yes exits 121, dry-run never asks.
func TestConfirmFloorsAndRefusals(t *testing.T) {
	var out strings.Builder
	// Floor refusal: 256MB required, 1MB free.
	proceed, code := Confirm(&out, nil, []PlanEntry{{Path: "x", SizeBytes: 1}}, nil, 256<<20, 1<<20, Options{Yes: true})
	if proceed || code != ExitState {
		t.Fatalf("floor: proceed=%v code=%d", proceed, code)
	}
	if !strings.Contains(out.String(), "preflight refused") {
		t.Fatalf("refusal copy: %q", out.String())
	}
	// Non-TTY without --yes: 121.
	out.Reset()
	proceed, code = Confirm(&out, nil, []PlanEntry{{Path: "x"}}, nil, 0, 1<<30, Options{})
	if proceed || code != ExitNotTTY {
		t.Fatalf("non-TTY: proceed=%v code=%d", proceed, code)
	}
	// --yes proceeds above floor.
	proceed, code = Confirm(&out, nil, []PlanEntry{{Path: "x"}}, nil, 256<<20, 1<<30, Options{Yes: true})
	if !proceed || code != ExitOK {
		t.Fatalf("--yes above floor: proceed=%v code=%d", proceed, code)
	}
}

// The noop runner refuses (zero budget) rather than hitting a real repo.
func newNoopGitRunner() gitx.Runner { return gitx.Runner{} }
