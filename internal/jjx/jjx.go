// Package jjx collects jj facts for the verdict matrix. Revsets are pinned
// against jj 0.44 (the installed version): unpushed is everything reachable
// from the working copy but not from any remote bookmark. Recency signals are
// deliberately file-based (.jj/repo/op_heads mtimes, the backing git store's
// FETCH_HEAD) rather than template exec: op-log templates churn across jj
// versions, file mtimes do not.
//
// jj being missing or failing is Unavailable — never "clean" — and the
// verdict matrix routes that to ignorance-class MANUAL.
package jjx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/config"
)

// Runner executes jj with a budget.
type Runner struct {
	Budget time.Duration
}

// Facts is the jj fact set for one candidate.
type Facts struct {
	Unavailable bool
	Why         string
	// UnpushedChanges counts commits in ::@ that no remote bookmark reaches.
	UnpushedChanges int
	// RemoteStale: remote bookmarks are older than the caller's window (or a
	// remote exists but no fetch marker does).
	RemoteStale bool
	// LastOp is the newest operation time (op-heads dir mtime).
	LastOp time.Time
	// Children lists workspace working-copy paths registered at this repo.
	Children []string
}

// Facts collects the jj fact set for dir (a repo with a .jj dir).
func (r Runner) Facts(dir string, now time.Time, remoteStaleAfter time.Duration) Facts {
	var f Facts
	if r.Budget <= 0 {
		f.Unavailable = true
		f.Why = "no jj exec budget configured"
		return f
	}

	// Push state: everything reachable from the working copy minus everything
	// any remote bookmark reaches, with EMPTY commits filtered out. The filter
	// is the whole game: jj keeps a standing (empty) working-copy change, so
	// without it every jj repo on earth would verdict BLOCKED forever. A dirty
	// working copy makes @ non-empty and counts (verified against jj 0.44);
	// described-but-empty commits are bookkeeping, not work. Pinned revset and
	// template:
	//   jj log -r '::@ ~ ::remote_bookmarks()' --no-graph \
	//        -T 'if(empty, "", commit_id ++ "\n")'
	out, err := r.run(dir, "log", "-r", "::@ ~ ::remote_bookmarks()", "--no-graph", "-T", `if(empty, "", commit_id ++ "\n")`)
	if err != nil {
		f.Unavailable = true
		f.Why = fmt.Sprintf("jj log: %v", err)
		return f
	}
	f.UnpushedChanges = len(nonEmpty(out))

	// Children: workspace list prints `<name>: <relative-path> <change-id>...`
	// (verified 0.44). The path is the first token after ": ", relative to the
	// parent; the default workspace ("." — the repo itself) is not a child.
	// Paths containing spaces would defeat the first-token split; workspace
	// roots with spaces are vanishingly rare and the miss fails soft (an
	// unreadable path simply never matches a candidate).
	if out, err := r.run(dir, "workspace", "list"); err == nil {
		for _, line := range nonEmpty(out) {
			i := strings.Index(line, ": ")
			if i < 0 {
				continue
			}
			fields := strings.Fields(line[i+2:])
			if len(fields) == 0 {
				continue
			}
			rel := fields[0]
			if rel == "." || rel == "(deleted)" {
				continue
			}
			p := rel
			if !filepath.IsAbs(p) {
				p = filepath.Join(dir, p)
			}
			p = filepath.Clean(p)
			// The default workspace is the repo itself: "." when jj runs from
			// inside, an absolute path when invoked via -R. Either way it is
			// the parent, not a child.
			if config.Canonical(p) == config.Canonical(dir) {
				continue
			}
			f.Children = append(f.Children, p)
		}
	}

	f.LastOp = opRecency(dir)
	f.RemoteStale = fetchStaleness(dir, now, remoteStaleAfter)
	return f
}

// WorkspaceForget deregisters a workspace from its parent (apply path; must
// succeed before rm per the spec).
func (r Runner) WorkspaceForget(parent, name string) error {
	_, err := r.run(parent, "workspace", "forget", name)
	return err
}

func (r Runner) run(dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, "jj", append([]string{"-R", dir}, args...)...)
	// cwd = the repo: jj prints workspace paths RELATIVE TO THE CWD, and the
	// parser below resolves them against dir. Running from anywhere else
	// makes the same repo produce different output depending on where reap
	// happened to be invoked.
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("timeout after %s", r.Budget)
	}
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// opRecency reads the newest mtime under .jj/repo/op_heads: every operation
// rewrites a head file, so the directory's content mtimes track activity
// without version-dependent templates.
func opRecency(dir string) time.Time {
	heads := filepath.Join(dir, ".jj", "repo", "op_heads")
	var newest time.Time
	entries, err := os.ReadDir(heads)
	if err != nil {
		return time.Time{}
	}
	for _, e := range entries {
		if fi, err := e.Info(); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest
}

// fetchStaleness resolves the backing git store's FETCH_HEAD: colocated repos
// keep it in ./.git, split repos under .jj/repo/store/git. A remote that
// exists with no fetch marker at all is the stalest state there is.
func fetchStaleness(dir string, now time.Time, after time.Duration) bool {
	markers := []string{
		filepath.Join(dir, ".git", "FETCH_HEAD"),
		filepath.Join(dir, ".jj", "repo", "store", "git", "FETCH_HEAD"),
	}
	for _, m := range markers {
		if fi, err := os.Stat(m); err == nil {
			return now.Sub(fi.ModTime()) > after
		}
	}
	return hasGitRemote(dir)
}

// hasGitRemote checks the backing config for any [remote "…"] section.
func hasGitRemote(dir string) bool {
	for _, cfg := range []string{
		filepath.Join(dir, ".git", "config"),
		filepath.Join(dir, ".jj", "repo", "store", "git", "config"),
	} {
		raw, err := os.ReadFile(cfg)
		if err != nil {
			continue
		}
		if strings.Contains(string(raw), "[remote ") || strings.Contains(string(raw), "[remote\t") {
			return true
		}
	}
	return false
}

// Available reports whether jj is on PATH.
func Available() bool {
	_, err := exec.LookPath("jj")
	return err == nil
}

func nonEmpty(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
