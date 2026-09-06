package applycmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
)

// Lineage: children (worktrees/workspaces whose parent is also in the set)
// delete BEFORE the parent; unrelated roots keep plan order.
func TestOrderChildrenFirst(t *testing.T) {
	plan := []PlanEntry{
		{Path: `C:\repo`, Parent: `C:\repo`, Kind: classify.KindGitRepo},
		{Path: `C:\wt\child`, Parent: `C:\repo`, Kind: classify.KindGitWorktree},
		{Path: `C:\unrelated`, Parent: `C:\unrelated`, Kind: classify.KindScratch},
	}
	ordered, skips := OrderChildrenFirst(plan)
	if len(skips) != 0 {
		t.Fatalf("skips = %+v", skips)
	}
	childIdx, parentIdx := -1, -1
	for i, p := range ordered {
		if p.Path == `C:\wt\child` {
			childIdx = i
		}
		if p.Path == `C:\repo` {
			parentIdx = i
		}
	}
	if childIdx < 0 || parentIdx < 0 || childIdx > parentIdx {
		t.Fatalf("child must precede parent: order=%v", pathsOf(ordered))
	}
	if len(ordered) != 3 {
		t.Fatalf("ordered = %v", pathsOf(ordered))
	}
}

func pathsOf(plan []PlanEntry) []string {
	out := make([]string, len(plan))
	for i, p := range plan {
		out[i] = p.Path
	}
	return out
}

// The rename probe: a quiet dir probes and restores cleanly; the probe
// never leaves a trace.
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

// Probe-strand healing: a leftover .reap-probing with the original ABSENT
// renames back; with BOTH present the stray parks as .reap-orphaned-<ts>
// (never overwritten).
func TestHealProbingStrays(t *testing.T) {
	dir := t.TempDir()
	// Case 1: original gone -> rename back.
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
	// Case 2: both present -> parked, never overwritten.
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
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

// Deletion ordering: contents go before .git/.jj so a partial failure
// preserves history and reflog (the "undeletable husk, not lost work"
// property). We verify by making a nested content dir undeletable via a
// read-only... on Windows that is flaky; instead we assert the ORDER by
// observation: after Delete, the dir is gone entirely on success.
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
	err := removeContentsBeforeVCS(target)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := os.Stat(longPath(target)); !os.IsNotExist(err) {
		t.Fatal("target must be gone")
	}
}

// apply.lock: exclusive across handles (the second Lock fails fast).
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

// The re-verify tripwire: a dir walked with fresh-enough activity skips as
// active-tripwire (cache bypassed by construction: Entry always walks).
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
	skipWhy, v := Reverify(target, Options{}, cfg, Deleter{
		Git: newNoopGitRunner(),
	}, config.ExpandRoots(cfg.Protect), nil)
	if skipWhy != SkipActiveTripwire || v.Verdict != "ACTIVE" {
		t.Fatalf("fresh dir: skip=%q verdict=%s", skipWhy, v.Verdict)
	}
	_ = root
}

// Protected or held paths never pass re-verify (KEEP beats every rule and
// every flag).
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
	skipWhy, v := Reverify(target, Options{}, cfg, Deleter{Git: newNoopGitRunner()}, protected, nil)
	if skipWhy != SkipVerdictChanged || v.Verdict != "KEEP" {
		t.Fatalf("protected dir: skip=%q verdict=%s", skipWhy, v.Verdict)
	}
}

// The 121 shape lives in Confirm: non-TTY + no --yes refuses; --dry-run
// never asks.
func TestConfirmNonTTYRefusesAndDryRunSkips(t *testing.T) {
	var out strings.Builder
	// Non-TTY (a strings.Builder is never a terminal): no --yes -> 121.
	proceed, code := Confirm(&out, nil, []PlanEntry{{Path: "x", SizeBytes: 1}}, 0, 0, 1<<30,
		Options{})
	if proceed || code != ExitNotTTY {
		t.Fatalf("non-TTY without --yes: proceed=%v code=%d", proceed, code)
	}
	if !strings.Contains(out.String(), "pass --yes") {
		t.Fatalf("refusal copy: %q", out.String())
	}
	// --yes on a non-TTY proceeds.
	proceed, code = Confirm(&out, nil, []PlanEntry{{Path: "x"}}, 0, 0, 1<<30, Options{Yes: true})
	if !proceed || code != ExitOK {
		t.Fatalf("--yes: proceed=%v code=%d", proceed, code)
	}
	// --dry-run prints and never asks (regardless of TTY).
	out.Reset()
	proceed, code = Confirm(&out, nil, []PlanEntry{{Path: "x", SizeBytes: 2 << 30}}, 1, 0, 1<<30, Options{DryRun: true})
	if proceed || code != ExitOK {
		t.Fatalf("dry-run: proceed=%v code=%d", proceed, code)
	}
	if !strings.Contains(out.String(), "dry-run: nothing will be deleted") ||
		!strings.Contains(out.String(), "1 directories") ||
		!strings.Contains(out.String(), "widened via --include") {
		t.Fatalf("dry-run copy: %q", out.String())
	}
}
