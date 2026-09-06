package jjx

import (
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
// the older `--colocated` spelling only if that fails.
func colocate(t *testing.T, dir string) {
	t.Helper()
	if out, err := exec.Command("jj", "git", "init", "--colocate", dir).CombinedOutput(); err == nil {
		return
	} else if !strings.Contains(string(out), "unexpected argument") {
		t.Fatalf("jj git init --colocate: %v\n%s", err, out)
	}
	if out, err := exec.Command("jj", "git", "init", "--colocated", dir).CombinedOutput(); err != nil {
		t.Fatalf("jj git init --colocated: %v\n%s", err, out)
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
