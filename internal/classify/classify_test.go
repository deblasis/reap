package classify

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitInit runs a real git init so the fixtures exercise the exact on-disk
// shapes reap will meet in the wild (git is a test dependency, same as the
// facts packages).
func gitInit(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "init", "-q", "-b", "main")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init %s: %v %s", dir, err, out)
	}
}

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v %s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestScratchPlain(t *testing.T) {
	dir := t.TempDir()
	if got := Dir(dir).Kind; got != KindScratch {
		t.Fatalf("plain dir = %s, want scratch (no-VCS-markers rule)", got)
	}
}

func TestGitRepo(t *testing.T) {
	dir := t.TempDir()
	gitInit(t, dir)
	info := Dir(dir)
	if info.Kind != KindGitRepo {
		t.Fatalf("kind = %s, want git-repo", info.Kind)
	}
	if info.ParentRepo != dir {
		t.Fatalf("ParentRepo = %q, want the dir itself", info.ParentRepo)
	}
}

func TestLinkedWorktreeAliveAndOrphanedByParentRemoval(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitInit(t, repo)
	gitCmd(t, repo, "config", "user.email", "t@t")
	gitCmd(t, repo, "config", "user.name", "t")
	gitCmd(t, repo, "commit", "--allow-empty", "-q", "-m", "x")
	wt := filepath.Join(base, "wt")
	gitCmd(t, repo, "worktree", "add", "-q", "--detach", wt)

	if got := Dir(wt).Kind; got != KindGitWorktree {
		t.Fatalf("live worktree kind = %s, want git-worktree", got)
	}

	// Orphan class 1: parent deleted entirely.
	if err := os.RemoveAll(repo); err != nil {
		t.Fatal(err)
	}
	if got := Dir(wt).Kind; got != KindGitWorktreeOrphaned {
		t.Fatalf("parent-gone worktree kind = %s, want git-worktree-orphaned", got)
	}
}

// The so755 class: parent alive, but the worktree's branch was deleted from
// the parent (routine after squash-merge), leaving a "ref:" HEAD with no
// backing ref. File-based detection must catch this without exec.
func TestWorktreeOrphanedByDeletedBranch(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitInit(t, repo)
	gitCmd(t, repo, "config", "user.email", "t@t")
	gitCmd(t, repo, "config", "user.name", "t")
	gitCmd(t, repo, "commit", "--allow-empty", "-q", "-m", "x")
	wt := filepath.Join(base, "wt")
	gitCmd(t, repo, "worktree", "add", "-q", "-b", "feature", wt)
	if got := Dir(wt).Kind; got != KindGitWorktree {
		t.Fatalf("pre-delete kind = %s", got)
	}
	// Deleting the branch behind the worktree's back breaks the HEAD ref.
	// git itself refuses `branch -D` for a checked-out branch, but this
	// on-disk state is exactly what a squash-merge cleanup or a prune on
	// another machine leaves behind, so the fixture removes the loose ref
	// directly — classification must notice, without exec.
	if err := os.Remove(filepath.Join(repo, ".git", "refs", "heads", "feature")); err != nil {
		t.Fatal(err)
	}
	if got := Dir(wt).Kind; got != KindGitWorktreeOrphaned {
		t.Fatalf("broken-branch worktree kind = %s, want git-worktree-orphaned", got)
	}
}

func TestJJColocatedAndPure(t *testing.T) {
	// Colocated: .jj dir + .git dir side by side.
	dir := t.TempDir()
	gitInit(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, ".jj"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Dir(dir).Kind; got != KindJJRepo {
		t.Fatalf("colocated kind = %s, want jj-repo", got)
	}

	// Pure jj root: .jj with a root-style repo pointer.
	pure := filepath.Join(t.TempDir(), "pure")
	if err := os.MkdirAll(filepath.Join(pure, ".jj"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pure, ".jj", "repo"), []byte(".\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Dir(pure).Kind; got != KindJJRepo {
		t.Fatalf("pure jj kind = %s, want jj-repo", got)
	}
}

func TestJJWorkspaceSplitAndOrphan(t *testing.T) {
	base := t.TempDir()
	main := filepath.Join(base, "main")
	if err := os.MkdirAll(filepath.Join(main, ".jj"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(main, ".jj", "repo"), []byte(".\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(filepath.Join(ws, ".jj"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".jj", "repo"), []byte(main+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info := Dir(ws)
	if info.Kind != KindJJWorkspace || info.ParentRepo != main {
		t.Fatalf("split workspace = %+v, want jj-workspace parent=%s", info, main)
	}

	if err := os.RemoveAll(main); err != nil {
		t.Fatal(err)
	}
	if got := Dir(ws).Kind; got != KindJJWorkspaceOrphaned {
		t.Fatalf("orphaned workspace kind = %s", got)
	}
}

// The .git file content is OS-shaped (git writes forward slashes); the parser
// must accept both spellings and bare-style parents.
func TestGitLinkParsing(t *testing.T) {
	parent, name, ok := worktreeParent(`C:/x/repo/.git/worktrees/so755`)
	if !ok || parent != `C:\x\repo` || name != "so755" {
		t.Fatalf("parse = %q %q %v", parent, name, ok)
	}
}

// The backendless half of the gating: a .jj pointer with NO .git anywhere
// classifies as jj with GitBackend=false, so the scan layer never execs git
// there. (jj 0.44 cannot create real split roots with default flags, so the
// synthetic shape — the same one classify sees in the wild via split
// workspace pointers — is the honest fixture.)
func TestDirBackendlessGate(t *testing.T) {
	base := t.TempDir()
	main := filepath.Join(base, "main")
	if err := os.MkdirAll(filepath.Join(main, ".jj"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(main, ".jj", "repo"), []byte(".\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(filepath.Join(ws, ".jj"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".jj", "repo"), []byte(main+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Dir(main).GitBackend; got {
		t.Error("backendless jj root must report GitBackend=false")
	}
	if got := Dir(ws).GitBackend; got {
		t.Error("backendless jj workspace must report GitBackend=false")
	}
	// Colocated (with .git) flips it true.
	if err := os.MkdirAll(filepath.Join(main, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := Dir(main).GitBackend; !got {
		t.Error("colocated root must report GitBackend=true")
	}
}
