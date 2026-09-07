package quarantine

import (
	crand "crypto/rand"
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
	session := filepath.Join(t.TempDir(), "s")
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
	session := filepath.Join(t.TempDir(), "s")
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

// Plain copy: capped, byte-for-byte, entries listed, priced.
func TestPlainCopy(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.bin"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	session := filepath.Join(t.TempDir(), "s")
	m, err := WritePlainCopy(session, src, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if m.Mode != "plain-copy" || len(m.Entries) != 1 {
		t.Fatalf("manifest: %+v", m)
	}
	if m.BundleBytes != 5 {
		t.Fatalf("plain copy not priced: %d", m.BundleBytes)
	}
	if b, _ := os.ReadFile(filepath.Join(session, "files", "a.bin")); string(b) != "hello" {
		t.Fatal("copy is not byte-for-byte")
	}
	// A pre-existing session dir is a typed collision, never an overwrite.
	if _, err := WritePlainCopy(session, src, 1<<20); err == nil || !strings.Contains(err.Error(), "same-named session") {
		t.Fatalf("want session-exists refusal, got %v", err)
	}
	// Cap refusal leaves nothing behind to mistake for a snapshot.
	if _, err := WritePlainCopy(filepath.Join(t.TempDir(), "s2"), src, 1); err == nil {
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
	session := filepath.Join(t.TempDir(), "s")
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
	session := filepath.Join(t.TempDir(), "s")
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
	session := filepath.Join(t.TempDir(), "s")
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
	if _, err := Snapshot(filepath.Join(t.TempDir(), "s"), repo, gr, Options{Mode: "bundle"}); err != nil {
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
	session := filepath.Join(t.TempDir(), "s")
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

// The round-2 live data-loss probe as a fixture: a repo whose ONLY ref to
// unpushed work is an ANNOTATED tag. The tag-object SHA never appears in
// the unpushed commit set, so membership must test the peeled target —
// the tagged commit must be recoverable from the bundle by name.
func TestSnapshotAnnotatedTagOnly(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("base"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "base")
	if err := os.WriteFile(filepath.Join(repo, "tagged.txt"), []byte("TAGGED-ONLY-WORK"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "tagged work")
	gitRun(t, repo, "tag", "-a", "v1", "-m", "release")
	// Point main back at the base: the tagged commit is reachable ONLY via
	// the annotated tag.
	gitRun(t, repo, "reset", "-q", "--hard", "HEAD~1")
	if _, err := os.Stat(filepath.Join(repo, "tagged.txt")); !os.IsNotExist(err) {
		t.Fatal("fixture: tagged.txt should be reset away")
	}

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	session := filepath.Join(t.TempDir(), "s")
	m, err := Snapshot(session, repo, gr, Options{Mode: "bundle"})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	refs := gitRun(t, repo, "for-each-ref", "--format=%(refname)", "refs/reap")
	if !strings.Contains(refs, "refs/reap/tag-v1") {
		t.Fatalf("annotated tag pin missing:\n%s", refs)
	}
	if m.Classes.Tags < 1 {
		t.Fatalf("tag count: %+v", m.Classes)
	}
	rec := t.TempDir()
	gitRun(t, rec, "init", "-q", "-b", "main")
	gitRun(t, rec, "fetch", "-q", filepath.Join(session, "bundle.git"), "refs/reap/*:refs/reap/*")
	shown := gitRun(t, rec, "show", "refs/reap/tag-v1:tagged.txt")
	if !strings.Contains(shown, "TAGGED-ONLY-WORK") {
		t.Fatalf("annotated-tag target NOT recoverable: %q", shown)
	}
}

// A QUIET repo must not report index interleaving: the restore's own write
// is un-done (mtime put back), and the interlock compares the mid-window
// observation, not the post-restore one (round-3 fix of the always-true
// fold).
func TestSnapshotInterleaveFalseQuiet(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	idx := filepath.Join(repo, ".git", "index")
	before, _ := os.Stat(idx)

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	m, err := Snapshot(filepath.Join(t.TempDir(), "s"), repo, gr, Options{Mode: "bundle"})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if m.Interleaved {
		t.Fatal("quiet repo reported index interleaving (false signal)")
	}
	// The capture must not freshen the index mtime: a refused discard must
	// not flip the dir ACTIVE for 48h.
	after, _ := os.Stat(idx)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("index mtime changed across capture: %v -> %v", before.ModTime(), after.ModTime())
	}
}

// RED-FIRST (round 4): a concurrent git's mid-window write IS detected.
// Deterministic through the readIndexBytes seam — a live race cannot be
// timed reliably, and the round-3 fold's fixture could only assert the
// quiet side (which is why the dead code survived a panel round).
func TestSnapshotInterleavedDetected(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}

	// The seam reports an index that DIFFERS from what reap saved — the
	// exact shape of a concurrent write landing inside the capture window.
	orig := readIndexBytes
	readIndexBytes = func(p string) ([]byte, error) {
		if b, err := orig(p); err == nil {
			return append([]byte("CONCURRENT-WRITE"), b...), nil
		}
		return orig(p)
	}
	defer func() { readIndexBytes = orig }()

	m, err := Snapshot(filepath.Join(t.TempDir(), "s"), repo, gr, Options{Mode: "bundle"})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !m.Interleaved {
		t.Fatal("concurrent index write NOT detected (the interlock is dead code again)")
	}
}

// The unborn HEAD (fresh git init, no commits) quarantines fine: the spec
// fixture the round-3 reflog error-propagation broke (git reflog show HEAD
// exits 128 there).
func TestSnapshotUnbornHead(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("ONLY COPY"), 0o644); err != nil {
		t.Fatal(err)
	}
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	session := filepath.Join(t.TempDir(), "s")
	m, err := Snapshot(session, repo, gr, Options{Mode: "bundle"})
	if err != nil {
		t.Fatalf("unborn HEAD must quarantine: %v", err)
	}
	if m.CaptureRef == "" {
		t.Fatal("no capture ref on the unborn shape")
	}
	// The capture tree materializes the untracked file.
	treeOf := gitRun(t, repo, "rev-parse", m.CaptureRef+"^{tree}")
	ls := gitRun(t, repo, "ls-tree", "--name-only", treeOf)
	if !strings.Contains(ls, "untracked.txt") {
		t.Fatalf("untracked-only tree not captured:\n%s", ls)
	}
}

// A pre-existing session dir is a same-name race: refusal naming it, never
// an overwrite of that dir's recovery.
func TestSnapshotSessionExistsRefusal(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	gitRun(t, repo, "commit", "-q", "--allow-empty", "-m", "one")
	session := filepath.Join(t.TempDir(), "taken")
	if err := os.MkdirAll(session, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(session, "bundle.git"), []byte("PRECIOUS"), 0o644); err != nil {
		t.Fatal(err)
	}
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	_, err := Snapshot(session, repo, gr, Options{Mode: "bundle"})
	if err == nil || !strings.Contains(err.Error(), "same-named session") {
		t.Fatalf("want same-named-session refusal, got %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(session, "bundle.git")); string(b) != "PRECIOUS" {
		t.Fatal("existing session was overwritten")
	}
}

// Capture-time base revalidation: a base force-pushed away on the remote
// produces the SELF-CONTAINED form — restorable from the bundle alone.
func TestSnapshotBaseGoneSelfContained(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("DIRTY"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Force the remote's history away: the recorded base is gone. The
	// bare's HEAD must move off main FIRST (it guards the current branch
	// from deletion).
	clone := filepath.Join(base, "clone")
	gitRun(t, base, "clone", "-q", bare, clone)
	if err := os.WriteFile(filepath.Join(clone, "other.txt"), []byte("orphan history"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, clone, "add", "-A")
	gitRun(t, clone, "commit", "-q", "--allow-empty", "-m", "unrelated root")
	gitRun(t, clone, "branch", "-M", "other")
	gitRun(t, clone, "push", "-q", "origin", "other")
	gitRun(t, bare, "symbolic-ref", "HEAD", "refs/heads/other")
	gitRun(t, clone, "push", "-q", "origin", "--delete", "main")

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	session := filepath.Join(t.TempDir(), "s")
	m, err := Snapshot(session, repo, gr, Options{Mode: "bundle"})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !m.SelfContained {
		t.Fatalf("base gone at capture must fall back self-contained: %+v", m)
	}
	// Restorable from the bundle ALONE (no remote base fetch).
	rec := t.TempDir()
	gitRun(t, rec, "init", "-q", "-b", "main")
	gitRun(t, rec, "fetch", "-q", filepath.Join(session, "bundle.git"), "refs/reap/*:refs/reap/*")
	shown := gitRun(t, rec, "show", m.CaptureRef+":f.txt")
	if !strings.Contains(shown, "DIRTY") {
		t.Fatalf("self-contained fallback not restorable standalone: %q", shown)
	}
}

// The round-4 fresh-install major as a red-first fixture: WritePlainCopy
// (and Snapshot) create their PARENT quarantine dir — before round 5 the
// exclusive session Mkdir failed against a missing parent on any state
// dir that had never seen a discard, making apply's carve-out a de-facto
// no-op on fresh installs.
func TestPlainCopyFreshStateDir(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.bin"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh := t.TempDir() // NO quarantine subdir exists
	session := SessionDir(fresh, src, time.Now())
	m, err := WritePlainCopy(session, src, 1<<20)
	if err != nil {
		t.Fatalf("fresh-state plain copy: %v", err)
	}
	if m.BundleBytes == 0 {
		t.Fatal("not priced")
	}
	// The bundle path too.
	repo := filepath.Join(t.TempDir(), "r")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	gitRun(t, repo, "commit", "-q", "--allow-empty", "-m", "one")
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	if _, err := Snapshot(SessionDir(fresh, repo, time.Now().Add(time.Second)), repo, gr, Options{Mode: "bundle"}); err != nil {
		t.Fatalf("fresh-state snapshot: %v", err)
	}
}

// The baseAdvertised no-remote inversion (round 4): a repo with a
// resolvable upstream-tracking ref but NO configured remote must take the
// SELF-CONTAINED form — the delta's prerequisites would be unfetchable
// (restore skips the base fetch when Origin is empty).
func TestSnapshotNoRemoteWithBaseSelfContained(t *testing.T) {
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
	// Local-tracking upstream: branch.main.remote = "." (no real remote).
	gitRun(t, repo, "config", "branch.main.remote", ".")
	gitRun(t, repo, "config", "branch.main.merge", "refs/heads/main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	session := SessionDir(t.TempDir(), repo, time.Now())
	m, err := Snapshot(session, repo, gr, Options{Mode: "bundle"})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !m.SelfContained {
		t.Fatalf("no-remote repo with a resolvable base must be self-contained: %+v", m)
	}
}

// A REFUSED capture on an unborn repo leaves no .git/index behind (the
// round-4 poison: reset --mixed CREATES one, flipping the dir ACTIVE for
// 48h — the refusal must leave the dir untouched, literally).
func TestSnapshotUnbornRefusedNoIndexPoison(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	big := make([]byte, 1<<20)
	if _, err := crand.Read(big); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	_, err := Snapshot(SessionDir(t.TempDir(), repo, time.Now()), repo, gr, Options{Mode: "bundle", CapBytes: 64 << 10})
	var tooLarge *ErrTooLarge
	if err == nil || !errors.As(err, &tooLarge) {
		t.Fatalf("want over-cap refusal, got %v", err)
	}
	if _, serr := os.Stat(filepath.Join(repo, ".git", "index")); serr == nil {
		t.Fatal("refused capture left a .git/index behind (ACTIVE poisoning)")
	}
}

// The unborn hoist RED-FIRST (round 7): fail AddAll on an unborn repo
// (locked file) and assert no .git/index survives the ERROR branch — the
// round-5 fixture refused at post-capture pricing, which the old
// success-tail cleanup already handled, so it could not fail on the bug.
func TestSnapshotUnbornAddAllFailNoIndex(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	big := make([]byte, 1<<20)
	if _, err := crand.Read(big); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(repo, "locked.bin")
	if err := os.WriteFile(victim, big, 0o644); err != nil {
		t.Fatal(err)
	}
	held, herr := holdNoShare(t, victim)
	if herr != nil {
		t.Skipf("cannot hold file: %v", herr)
	}
	defer held.Close()

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	_, err := Snapshot(filepath.Join(t.TempDir(), "s"), repo, gr, Options{Mode: "bundle"})
	if err == nil {
		t.Fatal("locked file must fail the capture")
	}
	if _, serr := os.Stat(filepath.Join(repo, ".git", "index")); serr == nil {
		t.Fatal("AddAll-failure path left a .git/index behind (ACTIVE poisoning on the error branch)")
	}
}

// Revalidate's three states, pinned: advertised base = verified-ok; base
// absent from a reachable remote = at-risk; unreachable remote =
// unverified (never conflated with at-risk).
func TestRevalidateStates(t *testing.T) {
	base := t.TempDir()
	bare := filepath.Join(base, "up.git")
	if err := os.MkdirAll(bare, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, bare, "init", "-q", "--bare", "-b", "main")
	seed := filepath.Join(base, "seed")
	if err := os.MkdirAll(seed, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, seed, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(seed, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, seed, "add", "-A")
	gitRun(t, seed, "commit", "-q", "-m", "x")
	gitRun(t, seed, "push", "-q", bare, "main")
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 30 * time.Second}
	tip := gitRun(t, bare, "rev-parse", "HEAD")

	if v := Revalidate(gr, &Manifest{BaseSHA: tip, Origin: bare}); v != VerifiedOK {
		t.Fatalf("advertised base: %v", v)
	}
	if v := Revalidate(gr, &Manifest{BaseSHA: strings.Repeat("0", 40), Origin: bare}); v != AtRisk {
		t.Fatalf("gone base: %v", v)
	}
	if v := Revalidate(gr, &Manifest{BaseSHA: tip, Origin: filepath.Join(base, "no-such-remote.git")}); v != Unverified {
		t.Fatalf("unreachable remote: %v", v)
	}
	if v := Revalidate(gr, &Manifest{SelfContained: true}); v != VerifiedOK {
		t.Fatalf("self-contained: %v", v)
	}
}

// Empty dirs are recorded RELATIVE and restore recreates them under the
// destination (bundle mode — the round-2 absolute-path fold was broken
// exactly here).
func TestSnapshotEmptyDirsRelative(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(filepath.Join(repo, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, repo, "add", "-A")
	gitRun(t, repo, "commit", "-q", "-m", "one")
	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	m, err := Snapshot(filepath.Join(t.TempDir(), "s"), repo, gr, Options{Mode: "bundle"})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	found := false
	for _, d := range m.EmptyDirs {
		if d == "emptydir" {
			found = true
		}
		if filepath.IsAbs(d) {
			t.Fatalf("absolute empty-dir path recorded: %q", d)
		}
	}
	if !found {
		t.Fatalf("empty dir not recorded: %v", m.EmptyDirs)
	}
}
