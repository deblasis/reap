package quarantine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deblasis/reap/internal/gitx"
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
	if len(removed) != 1 || !strings.HasSuffix(removed[0], "one") {
		t.Fatalf("prune: %v", removed)
	}
	if _, err := os.Stat(s2); err != nil {
		t.Fatal("prune removed the young session")
	}
}
