package jjx

import (
	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func needJJ(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj not on PATH; jj facts tests skip with a notice (spec allows)")
	}
}

func sh(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"JJ_USER=t", "JJ_EMAIL=t@t",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// colocate initializes jj in an existing git repo. jj 0.44 spells it
// `jj git init --colocate <dir>` (positional destination); the helper probes
// the older `--colocated` spelling only if that fails. A transient init
// failure (observed under heavy parallel suite load, round 3) retries once
// and then SKIPS with the stderr — a load-sensitive fixture must not make
// the required gate run non-deterministic.
func colocate(t *testing.T, dir string) {
	t.Helper()
	for _, spelling := range [][]string{{"--colocate"}, {"--colocated"}} {
		out, err := exec.Command("jj", "git", "init", spelling[0], dir).CombinedOutput()
		if err == nil {
			return
		}
		if strings.Contains(string(out), "unexpected argument") {
			continue
		}
		// Retry once (transient), then skip with the reason.
		out, err = exec.Command("jj", "git", "init", spelling[0], dir).CombinedOutput()
		if err == nil {
			return
		}
		t.Skipf("jj git init %s: %v\n%s", spelling[0], err, out)
	}
	t.Fatal("jj git init: no supported spelling")
}

// jjRoot gives jj-executing fixtures a SHORT temp root: t.TempDir names
// itself after the test, and jj's 128-hex op-store filenames under a long
// name cross MAX_PATH 260, which made round-8's headline pin
// deterministically self-skip (and is the root cause of the chronic
// "op-store write flakes under load" as TempDir suffixes grow).
func jjRoot(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "jj")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// TestWSideNoChildren: a workspace enumerates NO children (its parent is
// the default workspace's ROOT; siblings belong to the parent's row).
// Short name + short root: this test deterministically self-skipped under
// the default gate in round 8 (its 43-char name made the op path 261).
func TestWSideNoChildren(t *testing.T) {
	needJJ(t)
	base := jjRoot(t)
	parent := filepath.Join(base, "p")
	if out, err := exec.Command("jj", "git", "init", "--colocate", parent).CombinedOutput(); err != nil {
		t.Skipf("jj git init --colocate: %v\n%s", err, out)
	}
	ws1 := filepath.Join(base, "w1")
	if out, err := exec.Command("jj", "-R", parent, "workspace", "add", ws1).CombinedOutput(); err != nil {
		t.Skipf("jj workspace add: %v\n%s", err, out)
	}
	ws2 := filepath.Join(base, "w2")
	if out, err := exec.Command("jj", "-R", parent, "workspace", "add", ws2).CombinedOutput(); err != nil {
		t.Skipf("jj workspace add 2: %v\n%s", err, out)
	}
	r := Runner{Budget: 60 * time.Second}
	// From a workspace: no children at all (neither the parent nor the
	// sibling — both belong to the PARENT's row).
	f := r.Facts(ws1, time.Now(), 48*time.Hour)
	if len(f.Children) != 0 {
		t.Fatalf("workspace rows its own children: %v", f.Children)
	}
	// From the parent: both workspaces are children.
	fp := r.Facts(parent, time.Now(), 48*time.Hour)
	if len(fp.Children) != 2 {
		t.Fatalf("parent must keep both workspaces as children: %v", fp.Children)
	}
}

// The parent ROOT (not the .jj/repo dir) is what classify carries: `jj -R
// <root> workspace forget` is the shape jj accepts — pointing at the repo
// dir failed live ("no jj repo in ...").
func TestWorkspaceParentIsRootShape(t *testing.T) {
	needJJ(t)
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if out, err := exec.Command("jj", "git", "init", "--colocate", parent).CombinedOutput(); err != nil {
		t.Skipf("jj git init --colocate: %v\n%s", err, out)
	}
	ws := filepath.Join(base, "ws")
	if out, err := exec.Command("jj", "-R", parent, "workspace", "add", ws).CombinedOutput(); err != nil {
		t.Skipf("jj workspace add: %v\n%s", err, out)
	}
	info := classify.Dir(ws)
	if info.Kind != classify.KindJJWorkspace {
		t.Fatalf("kind: %s", info.Kind)
	}
	if info.ParentRepo == "" || strings.HasSuffix(filepath.ToSlash(info.ParentRepo), ".jj/repo") {
		t.Fatalf("ParentRepo must be the ROOT shape, got %q", info.ParentRepo)
	}
	// The shape jj accepts, live.
	if out, err := exec.Command("jj", "-R", info.ParentRepo, "workspace", "list").CombinedOutput(); err != nil {
		t.Fatalf("jj -R %s (root shape) must work: %v\n%s", info.ParentRepo, err, out)
	}
}

func TestUnpushedAndPushedStates(t *testing.T) {
	needJJ(t)
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	remote := filepath.Join(base, "remote.git")
	for _, d := range []string{repo, remote} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sh(t, repo, "git", "init", "-q", "-b", "main")
	sh(t, remote, "git", "init", "-q", "--bare", "-b", "main")
	colocate(t, repo)
	sh(t, repo, "git", "remote", "add", "origin", remote)

	// A REAL change (a file), then commit: non-empty, on no remote bookmark.
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, repo, "jj", "commit", "-m", "one")
	sh(t, repo, "jj", "bookmark", "set", "main", "-r", "@-")

	f := Runner{Budget: 30 * time.Second}.Facts(repo, time.Now(), 72*time.Hour)
	if f.Unavailable {
		t.Fatalf("jj facts unavailable: %s", f.Why)
	}
	if f.UnpushedChanges != 1 {
		t.Fatalf("UnpushedChanges=%d before push, want 1 (the a.txt change; the standing empty @ must not count)", f.UnpushedChanges)
	}
	if f.LastOp.IsZero() {
		t.Fatal("LastOp must come from op_heads mtimes")
	}

	// Push the bookmark, fetch: the change is on a remote bookmark and the
	// new working copy is empty, so unpushed drops to zero.
	sh(t, repo, "jj", "git", "push", "--all")
	sh(t, repo, "git", "fetch")
	f = Runner{Budget: 30 * time.Second}.Facts(repo, time.Now(), 72*time.Hour)
	if f.Unavailable {
		t.Fatalf("jj facts unavailable after push: %s", f.Why)
	}
	if f.UnpushedChanges != 0 {
		t.Fatalf("UnpushedChanges=%d after push+fetch, want 0", f.UnpushedChanges)
	}
	if f.RemoteStale {
		t.Fatal("fresh fetch must not read as stale")
	}
}

// A dirty working copy IS unpushed work: @ becomes non-empty and must count,
// mirroring git's dirty-files row.
func TestDirtyWorkingCopyCounts(t *testing.T) {
	needJJ(t)
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	sh(t, repo, "git", "init", "-q", "-b", "main")
	colocate(t, repo)

	f := Runner{Budget: 30 * time.Second}.Facts(repo, time.Now(), 72*time.Hour)
	if f.Unavailable {
		t.Fatalf("jj facts unavailable: %s", f.Why)
	}
	if f.UnpushedChanges != 0 {
		t.Fatalf("fresh repo with empty @ must read 0, got %d", f.UnpushedChanges)
	}
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	f = Runner{Budget: 30 * time.Second}.Facts(repo, time.Now(), 72*time.Hour)
	if f.UnpushedChanges != 1 {
		t.Fatalf("dirty @ must count as 1 unpushed change, got %d", f.UnpushedChanges)
	}
}

func TestRemoteStalenessByMarkerAge(t *testing.T) {
	needJJ(t)
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	remote := filepath.Join(base, "remote.git")
	for _, d := range []string{repo, remote} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sh(t, repo, "git", "init", "-q", "-b", "main")
	sh(t, remote, "git", "init", "-q", "--bare", "-b", "main")
	colocate(t, repo)
	sh(t, repo, "git", "remote", "add", "origin", remote)
	sh(t, repo, "git", "fetch", "-q")

	old := time.Now().Add(-100 * time.Hour)
	if err := os.Chtimes(filepath.Join(repo, ".git", "FETCH_HEAD"), old, old); err != nil {
		t.Fatal(err)
	}
	f := Runner{Budget: 30 * time.Second}.Facts(repo, time.Now(), 72*time.Hour)
	if !f.RemoteStale {
		t.Fatal("FETCH_HEAD older than the window must flag RemoteStale")
	}
}

func TestWorkspaceChildren(t *testing.T) {
	needJJ(t)
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	sh(t, repo, "git", "init", "-q", "-b", "main")
	colocate(t, repo)
	ws := filepath.Join(base, "ws")
	sh(t, repo, "jj", "workspace", "add", ws)

	f := Runner{Budget: 30 * time.Second}.Facts(repo, time.Now(), 72*time.Hour)
	if len(f.Children) != 1 {
		t.Fatalf("Children=%v, want exactly [%s] (the repo itself must not be its own child)", f.Children, ws)
	}
	if config.Canonical(f.Children[0]) != config.Canonical(ws) {
		t.Fatalf("Children=%v, want [%s]", f.Children, ws)
	}
}

func TestUnavailableWhenBudgetZero(t *testing.T) {
	needJJ(t)
	dir := t.TempDir()
	f := Runner{}.Facts(dir, time.Now(), 72*time.Hour)
	if !f.Unavailable {
		t.Fatal("zero-budget runner must refuse rather than run unbounded")
	}
}

// Colocated jj repo (jj 0.44 cannot create real split roots with default
// flags, so the honest fixture here is colocated; the BACKENDLESS half of
// the gating is pinned in classify's TestDirBackendlessGate plus the scan
// layer's synthetic-dir behavior). jj facts must read unpushed work.
func TestColocatedFactsWork(t *testing.T) {
	needJJ(t)
	base := t.TempDir()
	dir := filepath.Join(base, "coloc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("jj", "git", "init", "--colocate", dir).CombinedOutput(); err == nil {
		_ = out
	} else if out2, err2 := exec.Command("jj", "git", "init", "--colocated", dir).CombinedOutput(); err2 != nil {
		t.Skipf("cannot colocate: %v %s / %v %s", err, out, err2, out2)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sh(t, dir, "jj", "commit", "-m", "one")

	f := Runner{Budget: 30 * time.Second}.Facts(dir, time.Now(), 72*time.Hour)
	if f.Unavailable {
		t.Fatalf("colocated facts unavailable: %s", f.Why)
	}
	if f.UnpushedChanges != 1 {
		t.Fatalf("UnpushedChanges=%d, want 1", f.UnpushedChanges)
	}
}

// The dirty-tree stability case (the one that WRITES on snapshot): two
// Facts calls on an aged, dirty colocated repo must leave nothing under
// .jj or .git reading fresh — the round-3 panel proved clamping to the
// capture instant still flipped BLOCKED to ACTIVE on the next scan.
func TestDirtyTreeStableAcrossReads(t *testing.T) {
	needJJ(t)
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	sh(t, repo, "git", "init", "-q", "-b", "main")
	colocate(t, repo)
	sh(t, repo, "jj", "commit", "-m", "one")
	// A DIRTY working copy: the file exists uncommitted, so every push-state
	// query snapshots real state.
	if err := os.WriteFile(filepath.Join(repo, "wip.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}

	aged := time.Now().Add(-72 * time.Hour)
	for _, root := range []string{filepath.Join(repo, ".jj"), filepath.Join(repo, ".git")} {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err == nil {
				os.Chtimes(p, aged, aged)
			}
			return nil
		})
	}
	os.Chtimes(repo, aged, aged)
	os.Chtimes(filepath.Join(repo, "wip.txt"), aged, aged)

	r := Runner{Budget: 30 * time.Second}
	f1 := r.Facts(repo, time.Now(), 72*time.Hour)
	if f1.UnpushedChanges != 1 {
		t.Fatalf("first read must see the dirty change: %+v", f1)
	}
	time.Sleep(1100 * time.Millisecond)
	f2 := r.Facts(repo, time.Now(), 72*time.Hour)
	if f2.UnpushedChanges != 1 {
		t.Fatalf("second read must see the same change: %+v", f2)
	}
	freshest := time.Time{}
	for _, root := range []string{filepath.Join(repo, ".jj"), filepath.Join(repo, ".git")} {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if fi, e := d.Info(); e == nil && fi.ModTime().After(freshest) {
					freshest = fi.ModTime()
				}
			}
			return nil
		})
	}
	if time.Since(freshest) < 24*time.Hour {
		t.Fatalf("snapshot writes read as fresh (freshest %v): the next scan would flip this repo ACTIVE", freshest)
	}
}

// Consecutive-scan stability: two Facts calls on an aged repo must not
// advance the activity reap itself measures (op-heads/working-copy mtimes
// restored, files created by the snapshot clamped to the capture instant).
func TestRepeatReadsStable(t *testing.T) {
	needJJ(t)
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	sh(t, repo, "git", "init", "-q", "-b", "main")
	colocate(t, repo)
	sh(t, repo, "jj", "commit", "-m", "one")

	// Age the whole .jj tree well past the active window.
	aged := time.Now().Add(-72 * time.Hour)
	maxBefore := aged
	filepath.WalkDir(filepath.Join(repo, ".jj"), func(p string, d os.DirEntry, err error) error {
		if err == nil {
			os.Chtimes(p, aged, aged)
			if d.IsDir() {
				os.Chtimes(p, aged, aged)
			}
		}
		return nil
	})
	os.Chtimes(repo, aged, aged)

	r := Runner{Budget: 30 * time.Second}
	_ = r.Facts(repo, time.Now(), 72*time.Hour)
	time.Sleep(1100 * time.Millisecond) // cross a mtime tick boundary
	f2 := r.Facts(repo, time.Now(), 72*time.Hour)
	_ = maxBefore

	// After two full fact reads, the freshest thing under .jj must still
	// read as aged (the capture-instant clamp may add at most the first
	// call's timestamp — assert it is NOT "now fresh").
	freshest := time.Time{}
	filepath.WalkDir(filepath.Join(repo, ".jj"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, e := d.Info(); e == nil && fi.ModTime().After(freshest) {
				freshest = fi.ModTime()
			}
		}
		return nil
	})
	if time.Since(freshest) < 24*time.Hour {
		t.Fatalf("reap's own reads freshened .jj (freshest %v): consecutive scans would flip this repo ACTIVE", freshest)
	}
	if !f2.LastOp.Before(time.Now().Add(-time.Hour)) {
		t.Fatalf("LastOp advanced across reads: %v", f2.LastOp)
	}
}
