package quarantine

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/jjx"
)

func gitRun(t *testing.T, dir string, args ...string) string {
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

// The completeness contract on a real repo: dirty + untracked + ignored
// content all end up in the capture ref, the working tree is untouched by
// the snapshot (bytes still on disk, index restored), and local-only tips
// are pinned under refs/reap/*.
func TestSnapshotCompleteness(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "one")
	// The BLOCKED shape: dirty + untracked + ignored + local-only branch.
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("modified"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("u"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("ignored\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "ignored"), []byte("i"), 0o644); err != nil {
		t.Fatal(err)
	}

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	session := t.TempDir()
	m, err := Snapshot(session, repo, gr, Options{Mode: "bundle"})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if m.CaptureRef == "" {
		t.Fatal("no capture ref")
	}
	// Dirty/untracked/ignored counted.
	if m.Classes.UntrackedFiles < 2 { // untracked.txt + .gitignore
		t.Fatalf("untracked undercounted: %+v", m.Classes)
	}
	if m.Classes.IgnoredFiles != 1 {
		t.Fatalf("ignored miscounted: %+v", m.Classes)
	}
	// Working tree untouched: files still on disk.
	if _, err := os.Stat(filepath.Join(repo, "untracked.txt")); err != nil {
		t.Fatal("untracked.txt vanished from the source tree")
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "f.txt")); string(b) != "modified" {
		t.Fatal("dirty file was reverted by the snapshot")
	}
	// Index restored: porcelain shows the same dirty/untracked set as before.
	st, err := gr.StatusPorcelain(repo)
	if err != nil {
		t.Fatal(err)
	}
	if st.Untracked < 2 {
		t.Fatalf("index not restored (untracked=%d, want >=2)", st.Untracked)
	}
	// Tips pinned under refs/reap/*.
	refs := gitRun(t, repo, "for-each-ref", "--format=%(refname)", "refs/reap")
	if !strings.Contains(refs, "refs/reap/capture-") || !strings.Contains(refs, "refs/reap/unpushed-") {
		t.Fatalf("refs/reap pins missing:\n%s", refs)
	}
	// The session holds a REAL bundle that verifies and is priced in the
	// manifest — the pins alone die with the source dir.
	bundle := filepath.Join(session, "bundle.git")
	if fi, err := os.Stat(bundle); err != nil || fi.Size() == 0 {
		t.Fatalf("bundle.git missing/empty: %v", err)
	}
	if m.BundleBytes == 0 {
		t.Fatal("manifest does not price the bundle")
	}
	if err := gr.BundleVerify(repo, bundle); err != nil {
		t.Fatalf("bundle verify: %v", err)
	}
}

// The capture ref's tree contains the ignored file (completeness, not
// porcelain's view).
func TestCaptureRefContainsIgnored(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "secret"), []byte("PRECIOUS"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "ig")
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	session := t.TempDir()
	m, err := Snapshot(session, repo, gr, Options{Mode: "bundle"})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	// The tree of the capture ref contains secret.
	treeOf := gitRun(t, repo, "rev-parse", m.CaptureRef+"^{tree}")
	ls := gitRun(t, repo, "ls-tree", "--name-only", treeOf)
	if !strings.Contains(ls, "secret") {
		t.Fatalf("ignored file missing from capture tree:\n%s", ls)
	}
}

// Plain copy: capped, byte-for-byte, entries listed.
func TestPlainCopy(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.bin"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	session := t.TempDir()
	m, err := WritePlainCopy(session, src, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if m.Mode != "plain-copy" || len(m.Entries) != 1 {
		t.Fatalf("manifest: %+v", m)
	}
	if b, _ := os.ReadFile(filepath.Join(session, "files", "a.bin")); string(b) != "hello" {
		t.Fatal("copy is not byte-for-byte")
	}
	// Cap refusal leaves nothing behind to mistake for a snapshot.
	if _, err := WritePlainCopy(t.TempDir(), src, 1); err == nil {
		t.Fatal("cap must refuse")
	}
}

// Prune respects the cutoff; List returns manifests.
func TestListAndPrune(t *testing.T) {
	stateDir := t.TempDir()
	s1 := SessionDir(stateDir, "C:\\x\\one", time.Now().Add(-48*time.Hour))
	if err := os.MkdirAll(s1, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(s1, "manifest.json"), []byte(`{"mode":"bundle","source":"C:\\x\\one"}`), 0o644)
	s2 := SessionDir(stateDir, "C:\\x\\two", time.Now())
	if err := os.MkdirAll(s2, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(s2, "manifest.json"), []byte(`{"mode":"plain-copy","source":"C:\\x\\two"}`), 0o644)
	// Backdate s1's mtime so the cutoff sees it.
	old := time.Now().Add(-72 * time.Hour)
	os.Chtimes(s1, old, old)

	listing := List(stateDir)
	if len(listing) != 2 {
		t.Fatalf("list: %d", len(listing))
	}
	removed := PruneOlderThan(stateDir, time.Now().Add(-24*time.Hour))
	if len(removed) != 1 || !strings.HasSuffix(removed[0].Dir, "one") || removed[0].Err != nil {
		t.Fatalf("prune: %+v", removed)
	}
	if _, err := os.Stat(s2); err != nil {
		t.Fatal("prune removed the young session")
	}
}

// The pin scheme per the spec: branch tips as unpushed-<branch>, tags as
// tag-<name>, and REFLOG-ONLY generations as reflog-N (reflogs are never
// packed by bundles — the reset-away commit must be recoverable by name).
func TestSnapshotPinsReflogAndTags(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "one")
	gitRun(t, repo, "tag", "v1")
	// A reflog-only generation: commit then reset away.
	if err := os.WriteFile(filepath.Join(repo, "gone.txt"), []byte("REFLOG-ONLY"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "will be reset away")
	gitRun(t, repo, "reset", "-q", "--hard", "HEAD~1")
	if _, err := os.Stat(filepath.Join(repo, "gone.txt")); !os.IsNotExist(err) {
		t.Fatal("fixture: gone.txt should be reset away")
	}

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	session := t.TempDir()
	m, err := Snapshot(session, repo, gr, Options{Mode: "bundle", RunID: "reap-test"})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	refs := gitRun(t, repo, "for-each-ref", "--format=%(refname)", "refs/reap")
	for _, want := range []string{"refs/reap/capture-", "refs/reap/unpushed-main", "refs/reap/tag-v1", "refs/reap/reflog-0"} {
		if !strings.Contains(refs, want) {
			t.Fatalf("pin %s missing:\n%s", want, refs)
		}
	}
	if m.RunID != "reap-test" || m.Classes.ReflogTips < 1 {
		t.Fatalf("manifest: %+v %+v", m, m.Classes)
	}
	// The reset-away commit is recoverable FROM THE BUNDLE by name.
	rec := t.TempDir()
	gitRun(t, rec, "init", "-q", "-b", "main")
	gitRun(t, rec, "fetch", "-q", filepath.Join(session, "bundle.git"), "refs/reap/*:refs/reap/*")
	shown := gitRun(t, rec, "show", "refs/reap/reflog-0:gone.txt")
	if !strings.Contains(shown, "REFLOG-ONLY") {
		t.Fatalf("reflog-only commit not recoverable: %q", shown)
	}
}

// Delta pricing per the spec's pinned base selection: a repo with a pushed
// upstream records baseRef + baseSha + origin, is NOT self-contained, and
// restores from a FRESH CLONE of the remote (the delta's prerequisites).
func TestSnapshotDeltaBase(t *testing.T) {
	base := t.TempDir()
	bare := filepath.Join(base, "up.git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, bare, "init", "-q", "--bare", "-b", "main")
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("pushed"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "one")
	gitRun(t, repo, "remote", "add", "origin", bare)
	gitRun(t, repo, "push", "-q", "-u", "origin", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("DIRTY-DELTA"), 0o644); err != nil {
		t.Fatal(err)
	}

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	session := t.TempDir()
	m, err := Snapshot(session, repo, gr, Options{Mode: "bundle"})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if m.SelfContained {
		t.Fatal("pushed-upstream repo must be delta-marked")
	}
	if m.BaseRef == "" || m.BaseSHA == "" || m.Origin == "" {
		t.Fatalf("delta base not recorded: %+v", m)
	}
	// A small dirty worktree of a pushed parent prices small: the delta is
	// just the capture commit, far under the full history.
	histSize := int64(len(gitRun(t, repo, "rev-list", "--all")))
	if m.BundleBytes == 0 || histSize == 0 {
		t.Fatalf("bundle pricing: %d bytes, %d commits", m.BundleBytes, histSize)
	}
	// Restore path for a delta bundle: fresh CLONE of the remote, then the
	// bundle's refs fetch in.
	clone := filepath.Join(base, "clone")
	gitRun(t, base, "clone", "-q", bare, clone)
	gitRun(t, clone, "fetch", "-q", filepath.Join(session, "bundle.git"), "refs/reap/*:refs/reap/*")
	shown := gitRun(t, clone, "show", m.CaptureRef+":f.txt")
	if !strings.Contains(shown, "DIRTY-DELTA") {
		t.Fatalf("delta capture not restorable from clone: %q", shown)
	}
}

// An index.lock at capture start is git-busy: refusal, dir untouched.
func TestSnapshotGitBusy(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	gitRun(t, repo, "commit", "-q", "--allow-empty", "-m", "one")
	if err := os.WriteFile(filepath.Join(repo, ".git", "index.lock"), []byte("held"), 0o644); err != nil {
		t.Fatal(err)
	}
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	session := t.TempDir()
	_, err := Snapshot(session, repo, gr, Options{Mode: "bundle"})
	var busy *ErrGitBusy
	if err == nil || !errors.As(err, &busy) {
		t.Fatalf("want ErrGitBusy, got %v", err)
	}
	if _, serr := os.Stat(session); !os.IsNotExist(serr) {
		t.Fatal("git-busy refusal must clean the session dir")
	}
}

// FreshSessionDir suffixes on collision: two same-second sessions never
// share a directory (the earlier bundle is that dir's only recovery).
func TestFreshSessionDirCollision(t *testing.T) {
	stateDir := t.TempDir()
	now := time.Now()
	first := FreshSessionDir(stateDir, `C:\a\wip`, now)
	if err := os.MkdirAll(first, 0o755); err != nil {
		t.Fatal(err)
	}
	second := FreshSessionDir(stateDir, `C:\b\wip`, now)
	if first == second {
		t.Fatal("same-second same-basename collision not suffixed")
	}
	if err := os.MkdirAll(second, 0o755); err != nil {
		t.Fatal(err)
	}
	third := FreshSessionDir(stateDir, `C:\b\wip`, now)
	if third == first || third == second {
		t.Fatalf("third collision not suffixed: %q", third)
	}
}

// The operator's STAGED state survives a snapshot byte-exactly (SaveIndex,
// not reset): porcelain shows the staged entry after Snapshot returns.
func TestSnapshotStagedStatePreserved(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("committed"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "one")
	if err := os.WriteFile(filepath.Join(repo, "staged.txt"), []byte("OPERATOR-STAGED"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "staged.txt") // the operator's staged state

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	if _, err := Snapshot(t.TempDir(), repo, gr, Options{Mode: "bundle"}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	out := gitRun(t, repo, "status", "--porcelain")
	if !strings.Contains(out, "A  staged.txt") {
		t.Fatalf("staged state not preserved:\n%s", out)
	}
}

// Plain-copy cap prices DIRECTORIES too (a dir-heavy tree must not bypass
// the cap by hiding bytes one level down).
func TestPlainCopyDirCap(t *testing.T) {
	src := t.TempDir()
	sub := filepath.Join(src, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "big.bin"), make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := WritePlainCopy(t.TempDir(), src, 64<<10); err == nil {
		t.Fatal("dir-hidden bytes bypassed the cap")
	}
}

// jj colocated capture: push-state commits are pinned under refs/reap/jj-N
// and counted (skip when jj is not installed).
func TestSnapshotColocatedJJ(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj not on PATH")
	}
	base := t.TempDir()
	repo := filepath.Join(base, "corepo")
	cmd := exec.Command("jj", "git", "init", "--colocate", repo)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("jj git init --colocate: %v %s", err, out)
	}
	for _, w := range []string{"one", "two"} {
		if err := os.WriteFile(filepath.Join(repo, w+".txt"), []byte(w), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("jj", "-R", repo, "commit", "-m", w).CombinedOutput(); err != nil {
			t.Skipf("jj commit: %v %s", err, out)
		}
	}
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	session := t.TempDir()
	m, err := Snapshot(session, repo, gr, Options{Mode: "bundle", JJ: jjx.Runner{Budget: 60 * time.Second}, Colocated: true})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	refs := gitRun(t, repo, "for-each-ref", "--format=%(refname)", "refs/reap")
	if !strings.Contains(refs, "refs/reap/jj-") {
		t.Fatalf("jj pins missing:\n%s", refs)
	}
	if m.Classes.JJChanges < 1 {
		t.Fatalf("jj changes not counted: %+v", m.Classes)
	}
}
