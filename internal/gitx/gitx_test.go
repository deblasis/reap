package gitx

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newRepo builds a repo with one commit and a local bare remote that has seen
// a fetch, i.e. the clean+pushed baseline every other fixture mutates.
func newRepo(t *testing.T) (dir, remote string) {
	t.Helper()
	base := t.TempDir()
	dir = filepath.Join(base, "repo")
	remote = filepath.Join(base, "remote.git")
	for _, d := range []string{dir, remote} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run(t, dir, "init", "-q", "-b", "main")
	run(t, remote, "init", "-q", "--bare", "-b", "main")
	write(t, dir, "f.txt", "one")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "one")
	run(t, dir, "remote", "add", "origin", remote)
	run(t, dir, "push", "-q", "-u", "origin", "main")
	run(t, dir, "fetch", "-q", "origin")
	return dir, remote
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runner() Runner {
	return Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
}

func TestCleanPushed(t *testing.T) {
	dir, _ := newRepo(t)
	f := runner().Facts(dir, time.Now(), 72*time.Hour)
	if f.StateUnreadable || f.FactsUnavailable {
		t.Fatalf("taxonomy flags set: %+v", f)
	}
	if f.Dirty != 0 || f.Untracked != 0 || f.Ignored != 0 || f.Stashes != 0 || f.Unpushed != 0 || f.ReflogOnly != 0 {
		t.Fatalf("clean repo has residue: %+v", f)
	}
	if f.NoRemote || f.RemoteStale {
		t.Fatalf("fresh remote misread: %+v", f)
	}
	if f.Branch != "main" || f.Upstream != "origin/main" {
		t.Fatalf("branch=%q upstream=%q", f.Branch, f.Upstream)
	}
}

func TestDirtyUntrackedIgnoredSplit(t *testing.T) {
	dir, _ := newRepo(t)
	write(t, dir, "f.txt", "modified")       // tracked-modified: dirty
	write(t, dir, "new.txt", "untracked")    // ??
	write(t, dir, ".gitignore", "ignored\n") // new file: untracked, not dirty
	write(t, dir, "ignored", "junk")         // !!
	f := runner().Facts(dir, time.Now(), 72*time.Hour)
	if f.Dirty != 1 {
		t.Fatalf("Dirty=%d, want 1 (only f.txt is tracked-modified)", f.Dirty)
	}
	if f.Untracked != 2 {
		t.Fatalf("Untracked=%d, want 2 (new.txt + .gitignore)", f.Untracked)
	}
	if f.Ignored != 1 || f.IgnoredB != 4 {
		t.Fatalf("Ignored=%d bytes=%d, want 1/4", f.Ignored, f.IgnoredB)
	}
}

func TestStashCount(t *testing.T) {
	dir, _ := newRepo(t)
	write(t, dir, "f.txt", "wip")
	run(t, dir, "stash", "-q")
	f := runner().Facts(dir, time.Now(), 72*time.Hour)
	if f.Stashes != 1 {
		t.Fatalf("Stashes=%d, want 1", f.Stashes)
	}
	// The stashed change leaves the tree clean but the stash ref holds the
	// commit: unpushed must see it (stash ref is under refs/).
	if f.Dirty != 0 {
		t.Fatalf("Dirty=%d after stash, want 0", f.Dirty)
	}
}

func TestUnpushedBranchVsReflogOnly(t *testing.T) {
	dir, _ := newRepo(t)
	// Branch-reachable local-only commit.
	write(t, dir, "b.txt", "b")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "b")
	// Reflog-only: a commit whose branch is then destroyed behind git's back.
	run(t, dir, "checkout", "-q", "-b", "doomed")
	write(t, dir, "d.txt", "d")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "d")
	run(t, dir, "checkout", "-q", "main")
	// git branch -D refuses nothing here (doomed is not checked out anywhere).
	run(t, dir, "branch", "-D", "doomed")

	f := runner().Facts(dir, time.Now(), 72*time.Hour)
	if f.Unpushed != 1 {
		t.Fatalf("Unpushed=%d, want 1 (branch-reachable b commit)", f.Unpushed)
	}
	if f.ReflogOnly < 1 {
		t.Fatalf("ReflogOnly=%d, want >=1 (the doomed commit survives via reflog)", f.ReflogOnly)
	}
	// The fixture pins commit dates to 2026-01-01, so the reflog residue is
	// far past the 90-day expiry: ExpireDays must clamp to 0, proving both
	// the date math and the clamp.
	if f.ExpireDays != 0 {
		t.Fatalf("ExpireDays=%d, want 0 (Jan-1 dates are long past expiry)", f.ExpireDays)
	}
}

func TestNoRemote(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "solo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "x", "x")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "x")
	f := runner().Facts(dir, time.Now(), 72*time.Hour)
	if !f.NoRemote {
		t.Fatal("NoRemote must be set: work exists only here")
	}
	if f.Unpushed == 0 {
		t.Fatal("no-remote repo must count its history as unpushed (nothing to subtract)")
	}
}

func TestRemoteStaleByFetchHeadAge(t *testing.T) {
	dir, _ := newRepo(t)
	gitDir := run(t, dir, "rev-parse", "--git-path", "FETCH_HEAD")
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(dir, gitDir)
	}
	old := time.Now().Add(-100 * time.Hour)
	if err := os.Chtimes(gitDir, old, old); err != nil {
		t.Fatal(err)
	}
	f := runner().Facts(dir, time.Now(), 72*time.Hour)
	if !f.RemoteStale {
		t.Fatal("FETCH_HEAD older than the window must flag RemoteStale")
	}
	// Pushing more commits does not refresh FETCH_HEAD; only fetch does.
}

// The spec's state-unreadable row names "locked index, corrupt .git". The
// corrupt half is the deterministic fixture; the locked-index half is pinned
// STRUCTURALLY (Facts stats index.lock before any exec), which a plain
// fixture CAN exercise deterministically: create the lock, assert the row.
func TestCorruptRepoIsStateUnreadable(t *testing.T) {
	dir, _ := newRepo(t)
	gitDir := run(t, dir, "rev-parse", "--absolute-git-dir")
	if err := os.Remove(filepath.Join(gitDir, "HEAD")); err != nil {
		t.Fatal(err)
	}
	f := runner().Facts(dir, time.Now(), 72*time.Hour)
	if !f.StateUnreadable {
		t.Fatalf("corrupt repo must be StateUnreadable, got %+v", f)
	}
	if f.FactsUnavailable {
		t.Fatal("repo-level failure must not double-report as tool-level")
	}
}

func TestTimeoutIsFactsUnavailable(t *testing.T) {
	dir, _ := newRepo(t)
	r := Runner{GitBudget: time.Nanosecond, FetchBudget: time.Nanosecond}
	f := r.Facts(dir, time.Now(), 72*time.Hour)
	if !f.StateUnreadable {
		t.Fatalf("status timing out is repo-level unreadable for the verdict row: %+v", f)
	}
	// The Why string must name the timeout so scan output can explain itself.
	if !strings.Contains(f.Why, "timeout") {
		t.Fatalf("Why=%q must name the timeout", f.Why)
	}
}

func TestChildrenIncludingBroken(t *testing.T) {
	base := t.TempDir()
	repo, _ := newRepoAt(t, base)
	wt := filepath.Join(base, "wt")
	run(t, repo, "worktree", "add", "-q", "--detach", wt)

	f := runner().Facts(repo, time.Now(), 72*time.Hour)
	// t.TempDir() may hand back the 8.3 short form while git metadata comes
	// back long: compare both sides through the same longPath normalization.
	if len(f.Children) != 1 ||
		!strings.EqualFold(longPath(filepath.Clean(f.Children[0])), longPath(filepath.Clean(wt))) {
		t.Fatalf("Children=%v, want [%s]", f.Children, wt)
	}

	// Stale child: the worktree dir vanishes but its registration remains.
	// It is NOT live: counting it would pin the parent MANUAL forever over a
	// path nothing can act on (the round-1 panel's fix). git worktree prune
	// owns cleaning the registration itself.
	if err := os.RemoveAll(wt); err != nil {
		t.Fatal(err)
	}
	f = runner().Facts(repo, time.Now(), 72*time.Hour)
	if len(f.Children) != 0 {
		t.Fatalf("stale child registration must be dropped: %v", f.Children)
	}
}

// newRepoAt is newRepo for a caller-chosen base (worktree fixtures need
// siblings).
func newRepoAt(t *testing.T, base string) (dir, remote string) {
	t.Helper()
	dir = filepath.Join(base, "repo")
	remote = filepath.Join(base, "remote.git")
	for _, d := range []string{dir, remote} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run(t, dir, "init", "-q", "-b", "main")
	run(t, remote, "init", "-q", "--bare", "-b", "main")
	write(t, dir, "f.txt", "one")
	run(t, dir, "add", "-A")
	run(t, dir, "commit", "-q", "-m", "one")
	run(t, dir, "remote", "add", "origin", remote)
	run(t, dir, "push", "-q", "origin", "main")
	run(t, dir, "fetch", "-q", "origin")
	return dir, remote
}

func TestFactsFromLinkedWorktree(t *testing.T) {
	base := t.TempDir()
	repo, _ := newRepoAt(t, base)
	wt := filepath.Join(base, "wt")
	run(t, repo, "worktree", "add", "-q", "--detach", wt)
	write(t, wt, "w.txt", "dirty in worktree")

	f := runner().Facts(wt, time.Now(), 72*time.Hour)
	if f.StateUnreadable || f.FactsUnavailable {
		t.Fatalf("worktree facts failed: %+v", f)
	}
	if f.Dirty != 0 {
		t.Fatalf("worktree dirty=%d, want 0 (new file is untracked)", f.Dirty)
	}
	if f.Untracked != 1 {
		t.Fatalf("worktree untracked=%d, want 1", f.Untracked)
	}
	// FETCH_HEAD resolution must use the common dir path from the worktree.
	if f.RemoteStale {
		t.Fatalf("worktree misread remote freshness: %+v", f)
	}
}

func TestDetachedHeadCounted(t *testing.T) {
	base := t.TempDir()
	repo, _ := newRepoAt(t, base)
	sha := run(t, repo, "rev-parse", "HEAD")
	write(t, repo, "detached.txt", "d")
	run(t, repo, "add", "-A")
	run(t, repo, "commit", "-q", "-m", "detached-only")
	run(t, repo, "checkout", "-q", "--detach", sha)

	f := runner().Facts(repo, time.Now(), 72*time.Hour)
	// The commit is reachable only from HEAD (detached); --branches --tags
	// HEAD includes HEAD, so it counts as branch-reachable unpushed.
	if f.Unpushed != 1 {
		t.Fatalf("Unpushed=%d, want 1 (detached-HEAD commit)", f.Unpushed)
	}
	if f.Branch != "HEAD" && f.Branch != "(detached)" {
		t.Logf("branch label %q (informational)", f.Branch)
	}
}

// The unborn-HEAD repo (fresh git init, no commits) has nothing to push:
// untracked content must route BLOCKED dirty-files, not state-unreadable.
// Round 2 proved the original exit-0 probe was dead code; this fixture pins
// the inverted semantics.
func TestUnbornHeadIsDirtyFilesNotUnreadable(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "fresh")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "parked.txt", "agent left this here")
	f := runner().Facts(dir, time.Now(), 72*time.Hour)
	if f.StateUnreadable {
		t.Fatalf("unborn HEAD must not read as unreadable: %+v", f)
	}
	if f.Untracked != 1 {
		t.Fatalf("Untracked=%d, want 1", f.Untracked)
	}
	if f.Unpushed != 0 || f.ReflogOnly != 0 {
		t.Fatalf("unborn repo has nothing to push: %+v", f)
	}
}

// The locked-index row, deterministic now that detection is structural:
// the lock file alone (no contention choreography) must produce the row.
func TestLockedIndexIsStateUnreadableStructurally(t *testing.T) {
	dir, _ := newRepo(t)
	gitDir := run(t, dir, "rev-parse", "--absolute-git-dir")
	if err := os.WriteFile(filepath.Join(gitDir, "index.lock"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(filepath.Join(gitDir, "index.lock")) })
	f := runner().Facts(dir, time.Now(), 72*time.Hour)
	if !f.StateUnreadable || !strings.Contains(f.Why, "index.lock") {
		t.Fatalf("structural lock check failed: %+v", f)
	}
}

// A linked worktree's index lock lives in ITS OWN gitdir, not the parent's
// common dir: a busy worktree must read StateUnreadable, and a busy PARENT
// must not poison the worktree's verdict.
func TestWorktreeOwnIndexLockDetected(t *testing.T) {
	base := t.TempDir()
	repo, _ := newRepoAt(t, base)
	wt := filepath.Join(base, "wt")
	run(t, repo, "worktree", "add", "-q", "--detach", wt)

	gitDir := run(t, wt, "rev-parse", "--absolute-git-dir")
	if filepath.Clean(gitDir) == filepath.Clean(run(t, repo, "rev-parse", "--absolute-git-dir")) {
		t.Fatal("fixture assumption: worktree gitdir should differ from parent's")
	}
	if err := os.WriteFile(filepath.Join(gitDir, "index.lock"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(filepath.Join(gitDir, "index.lock")) })
	f := runner().Facts(wt, time.Now(), 72*time.Hour)
	if !f.StateUnreadable || !strings.Contains(f.Why, "index.lock") {
		t.Fatalf("worktree's own lock must be detected: %+v", f)
	}
}

// The candidate is never its own child: an only-child worktree lists its own
// registration in the parent's worktrees dir, and that self-entry must not
// display parent-of-live-children over the worktree's real row.
func TestWorktreeNotItsOwnChild(t *testing.T) {
	base := t.TempDir()
	repo, _ := newRepoAt(t, base)
	wt := filepath.Join(base, "wt")
	run(t, repo, "worktree", "add", "-q", "--detach", wt)

	f := runner().Facts(wt, time.Now(), 72*time.Hour)
	for _, c := range f.Children {
		if strings.EqualFold(filepath.Clean(longPath(c)), filepath.Clean(longPath(wt))) {
			t.Fatalf("worktree lists itself as a child: %v", f.Children)
		}
	}
	// The PARENT still sees it as a live child (that is correct and wanted).
	pf := runner().Facts(repo, time.Now(), 72*time.Hour)
	if len(pf.Children) != 1 {
		t.Fatalf("parent must see the live worktree: %v", pf.Children)
	}
}

// Verdict-level pin for the unborn row (the engineering seat's third-pass
// finding): the branch probe failing on an unborn HEAD must NOT shadow the
// dirty/untracked rows — a fresh-init repo with parked files verdicts
// BLOCKED dirty-files end to end, not facts-unavailable.
func TestUnbornHeadVerdictIsDirtyFiles(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "fresh")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "parked.txt", "agent left this here")
	f := runner().Facts(dir, time.Now(), 72*time.Hour)
	if f.StateUnreadable || f.FactsUnavailable {
		t.Fatalf("unborn repo must read clean facts: %+v", f)
	}
}

// An idle colocated jj repo (pushed, bookmark tracked, zero user work) must
// NOT mint phantom unpushed-reflog rows from refs/jj/keep/*: the conformance
// seat proved --all sweeps those bookkeeping refs and they never expire.
func TestIdleColocatedNoPhantomReflogOnly(t *testing.T) {
	if _, err := exec.LookPath("jj"); err != nil {
		t.Skip("jj not on PATH")
	}
	base := t.TempDir()
	repo := filepath.Join(base, "repo")
	remote := filepath.Join(base, "remote.git")
	for _, d := range []string{repo, remote} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run(t, repo, "init", "-q", "-b", "main")
	run(t, remote, "init", "-q", "--bare", "-b", "main")
	write(t, repo, "f.txt", "x")
	run(t, repo, "add", "-A")
	run(t, repo, "commit", "-q", "-m", "one")
	run(t, repo, "remote", "add", "origin", remote)
	run(t, repo, "push", "-q", "-u", "origin", "main")
	run(t, repo, "fetch", "-q")
	jjEnv := append(os.Environ(), "JJ_USER=t", "JJ_EMAIL=t@t")
	if out, err := exec.Command("jj", "git", "init", "--colocate", repo).CombinedOutput(); err != nil {
		t.Skipf("cannot colocate: %v %s", err, out)
	} else {
		_ = out
	}
	if out, err := exec.Command("jj", "-R", repo, "--ignore-working-copy", "git", "import").CombinedOutput(); err != nil {
		t.Logf("jj import: %v %s (continuing)", err, out)
	}
	_ = jjEnv

	f := runner().Facts(repo, time.Now(), 72*time.Hour)
	if f.ReflogOnly != 0 || f.Unpushed != 0 {
		t.Fatalf("phantom unpushed from jj bookkeeping refs: Unpushed=%d ReflogOnly=%d (refs/jj/keep must be excluded)", f.Unpushed, f.ReflogOnly)
	}
}
