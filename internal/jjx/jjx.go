// Package jjx collects jj facts for the verdict matrix. Revsets are pinned
// against jj 0.44 (the installed version): unpushed is everything reachable
// from the working copy but not from any remote bookmark. Recency signals are
// deliberately file-based (.jj/repo/op_heads mtimes, the backing git store's
// FETCH_HEAD) rather than template exec: op-log templates churn across jj
// versions, file mtimes do not.
//
// jj being missing or failing is Unavailable  -  never "clean"  -  and the
// verdict matrix routes that to ignorance-class MANUAL.
package jjx

import (
	"sort"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/jjpaths"
)

// Runner executes jj with a budget.
type Runner struct {
	Budget time.Duration
}

// Facts is the jj fact set for one candidate.
type Facts struct {
	Unavailable bool
	Why         string
	// Deregistered: the workspace's parent is alive but this working copy
	// is no longer in its registry (the forget-then-rm crash window): jj
	// fails with "doesn't have a working-copy commit". Without this flag
	// the row lands facts-unavailable  -  the one verdict class with no
	// deletion path  -  instead of orphaned-workspace, which the carve-out
	// covers.
	Deregistered bool
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

// OpHeadNames lists the op-head file names under a repo's op_heads dir -
// the FILE-BASED op identity (template exec for op ids churns across jj
// versions; names do not). A genuine later op (fetch, import, another
// workspace's commit) adds a name the caller did not capture.
func OpHeadNames(repoDir string) []string {
	entries, err := os.ReadDir(filepath.Join(repoDir, ".jj", "repo", "op_heads"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
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
	// working copy makes @ non-empty and counts  -  which REQUIRES the snapshot
	// (--ignore-working-copy would hide unsaved working-copy edits from ::@).
	// The snapshot rewrites op_heads, i.e. reap's own read freshens the
	// activity it measures, so the mtimes are captured before and restored
	// after: honest facts AND no self-poisoning.
	restore := captureOpHeads(dir)
	out, err := r.runSnapshotting(dir, "log", "-r", "::@ ~ ::remote_bookmarks()", "--no-graph", "-T", `if(empty, "", commit_id ++ "\n")`)
	if err != nil {
		restore()
		f.Unavailable = true
		f.Why = fmt.Sprintf("jj log: %v", err)
		// The deregistered-but-standing shape (forget succeeded, the rm
		// crashed): the parent is alive, this dir is out of its registry,
		// and jj refuses with "doesn't have a working-copy commit".
		// Route it to the carve-out, not the no-deletion-path ignorance
		// class (the round-8 reliability finding).
		if strings.Contains(err.Error(), "doesn't have a working-copy commit") {
			f.Deregistered = true
		}
		return f
	}
	f.UnpushedChanges = len(nonEmpty(out))
	// Metadata-only reads below must not snapshot: --ignore-working-copy.
	restore()

	// Children: workspace list prints `<name>: <relative-path> <change-id>...`
	// (verified 0.44). The path is the first token after ": ", relative to the
	// parent; the default workspace ("."  -  the repo itself) is not a child.
	// Children are enumerated ONLY for the DEFAULT workspace (the repo root):
	// run from a workspace, the list prints the PARENT ROOT for the default
	// entry (never matching the .jj/repo pointer's REPO-DIR shape  -  the
	// round-7 no-op) and every SIBLING workspace too, none of which are this
	// dir's children. The shared jjpaths resolver supplies the parent root
	// in the one shape `workspace list` actually prints.
	layout, _ := jjpaths.Resolve(dir)
	if layout.ParentRoot == "" {
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
				// The default workspace is the repo itself: "." when jj runs
				// from inside, an absolute path when invoked via -R. Either
				// way it is the parent, not a child.
				if config.Canonical(p) == config.Canonical(dir) {
					continue
				}
				f.Children = append(f.Children, p)
			}
		}
	}

	f.LastOp = opRecency(dir)
	f.RemoteStale = fetchStaleness(dir, now, remoteStaleAfter)
	return f
}

// captureOpHeads records mtimes across everything the push-state snapshot
// touches and returns a restore func. The panel proved, across three rounds,
// that the snapshot writes: op_heads, .jj/working_copy/tree_state, and  -  in
// colocated repos  -  git objects and the index under .git. The restore:
// (a) resets every pre-existing file to its captured mtime, and (b) clamps
// files CREATED by the snapshot (mtime newer than the capture instant) to
// the tree's PRE-SCAN freshest mtime  -  clamping to the capture instant
// (round 2) still read as fresh activity to the next walk and flipped dirty
// jj repos BLOCKED to ACTIVE on every subsequent scan. Residual, documented:
// file CONTENT the snapshot wrote is real state; only its apparent age is
// undone, and the very first scan of a never-scanned dirty repo still does
// one snapshot's worth of work.
func captureOpHeads(dir string) func() {
	roots := []string{filepath.Join(dir, ".jj")}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		roots = append(roots, filepath.Join(dir, ".git"))
	}
	captureAt := time.Now()
	preScanNewest := time.Time{} // freshest mtime that existed before reap ran
	type stamp struct {
		path string
		at   time.Time
	}
	var stamps []stamp
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if fi, err := d.Info(); err == nil {
				stamps = append(stamps, stamp{p, fi.ModTime()})
				if fi.ModTime().After(preScanNewest) && !fi.ModTime().After(captureAt) {
					preScanNewest = fi.ModTime()
				}
			}
			return nil
		})
	}
	if preScanNewest.IsZero() {
		preScanNewest = captureAt
	}
	clampTo := preScanNewest
	return func() {
		for _, s := range stamps {
			os.Chtimes(s.path, s.at, s.at)
		}
		for _, root := range roots {
			filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				if fi, err := d.Info(); err == nil && fi.ModTime().After(captureAt) {
					os.Chtimes(p, clampTo, clampTo)
				}
				return nil
			})
		}
	}
}

// PushStateCommits returns the git SHAs of every non-empty commit reachable
// from the working copy that no remote bookmark reaches  -  the SAME revset
// the jj-unpushed fact counts, so quarantine pins exactly what the verdict
// was holding. Snapshotting (a dirty @ must be visible) with op-heads mtime
// restore, exactly like Facts.
func (r Runner) PushStateCommits(dir string) ([]string, error) {
	if r.Budget <= 0 {
		return nil, fmt.Errorf("no jj exec budget configured")
	}
	restore := captureOpHeads(dir)
	out, err := r.runSnapshotting(dir, "log", "-r", "::@ ~ ::remote_bookmarks()", "--no-graph", "-T", `if(empty, "", commit_id ++ "\n")`)
	restore()
	if err != nil {
		return nil, fmt.Errorf("jj log: %w", err)
	}
	return nonEmpty(out), nil
}

// GitExport exports jj state to the colocated git backend's refs, making
// jj-only commits and bookmarks visible to git rev-list/update-ref  -  the
// precondition for pinning refs/reap/jj-N through the git backend (one
// namespace rule for everything recoverable).
func (r Runner) GitExport(dir string) error {
	_, err := r.run(dir, "git", "export")
	return err
}

// WorkspaceForget deregisters a workspace from its parent (apply path; must
// succeed before rm per the spec).
func (r Runner) WorkspaceForget(parent, name string) error {
	_, err := r.run(parent, "workspace", "forget", name)
	return err
}

// WorkspaceListNames resolves workspace name -> working-copy path from the
// parent's registry (the dir base need not equal the registered name).
func (r Runner) WorkspaceListNames(parent string) map[string]string {
	out, err := r.run(parent, "workspace", "list")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, line := range nonEmpty(out) {
		i := strings.Index(line, ": ")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		fields := strings.Fields(line[i+2:])
		if len(fields) == 0 || name == "" || name == "default" {
			continue
		}
		p := fields[0]
		if p == "." || p == "(deleted)" {
			continue
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(parent, p)
		}
		m[name] = filepath.Clean(p)
	}
	return m
}

func (r Runner) run(dir string, args ...string) (string, error) {
	return r.runFlags([]string{"--ignore-working-copy"}, dir, args...)
}

// runSnapshotting runs WITHOUT --ignore-working-copy: the one query that
// must see the working copy as it stands (push state). Facts() wraps every
// snapshotting call with op-heads mtime restore.
func (r Runner) runSnapshotting(dir string, args ...string) (string, error) {
	return r.runFlags(nil, dir, args...)
}

func (r Runner) runFlags(prefix []string, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Budget)
	defer cancel()
	// --ignore-working-copy by default: read-only queries must not snapshot
	// the working copy (every snapshot rewrites op_heads and freshens the
	// activity reap measures). The push-state query opts back IN to
	// snapshotting (it must see a dirty @) and restores op-heads mtimes
	// around itself; every other call stays lock-free-read-only.
	full := append(append([]string{}, prefix...), "-R", dir)
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "jj", full...)
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
