// Package gitx collects every git fact the verdict matrix consumes, through
// exec with per-call budgets. Its contract is the taxonomy from the design
// spec: a repo-level failure (status or rev-list cannot run: locked index,
// corrupt .git) is StateUnreadable; any other failure (git missing, timeout,
// unparseable output) is FactsUnavailable. Neither may ever read as "clean":
// missing evidence weakens a verdict toward MANUAL, never toward SAFE.
package gitx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/walk"
)

// Runner executes git with budgets. The zero Runner refuses to run (zero
// budgets mean "cannot enforce a bound", and an unbounded exec can hang a
// one-shot scan on a single wedged repo).
type Runner struct {
	GitBudget   time.Duration
	FetchBudget time.Duration
}

// Facts is the full git fact set for one candidate directory. The zero value
// with both failure flags false and real counts means "read successfully";
// callers must check the failure flags before trusting any count.
type Facts struct {
	Dirty       int
	Untracked   int
	Ignored     int
	IgnoredCap  bool  // ignored-bytes walk hit its entry cap (lower bound)
	IgnoredB    int64 // bytes under ignored entries
	Stashes     int
	Unpushed    int    // branch/tag/HEAD-reachable commits not on any remote
	ReflogOnly  int    // commits reachable only via reflog (post-reset, pre-rebase)
	ExpireDays  int    // days until the oldest reflog-only commit ages out (90d default expiry)
	Branch      string // current branch name, "(detached)" on a detached HEAD
	Upstream    string // upstream tracking ref, empty when none
	NoRemote    bool
	RemoteStale bool      // FETCH_HEAD older than the caller's threshold
	LastFetch   time.Time // zero when no FETCH_HEAD exists
	HEAD        string
	LastCommit  time.Time
	Children    []string // registered worktree paths (file-based enumeration, includes broken)
	// Taxonomy. StateUnreadable outranks FactsUnavailable: the matrix's
	// state-unreadable row must shadow facts-unavailable, not the reverse.
	StateUnreadable  bool
	FactsUnavailable bool
	Why              string
}

// reflogExpiryDays matches git's default gc.reflogExpire (90 days). It is an
// approximation for the reason detail, not a correctness claim.
const reflogExpiryDays = 90

// ignoredBytesCap bounds the per-entry size walk for ignored paths: the
// verdict only needs presence; the byte detail must not multiply scan time on
// repos with hundreds of ignored build dirs.
const ignoredBytesCap = 64

// Facts collects the fact set for dir.
func (r Runner) Facts(dir string, now time.Time, remoteStaleAfter time.Duration) Facts {
	var f Facts

	// Status: repo-level failure if it cannot run. A live index.lock is
	// detected STRUCTURALLY, before any exec: with optional locks disabled
	// (below) git never takes or waits on that lock, so the only honest way
	// to see "a concurrent git holds the index" is to look for the file  -
	// in the worktree's OWN gitdir (linked worktrees keep their index there)
	// and in the common dir.
	if gi, ok := gitDirFor(dir); ok {
		if _, err := os.Stat(filepath.Join(gi, "index.lock")); err == nil {
			f.StateUnreadable = true
			f.Why = "index.lock present (a concurrent git is mid-write)"
			f.Children = fileChildren(dir)
			return f
		}
	}
	if common, ok := gitCommonDir(dir); ok {
		if _, err := os.Stat(filepath.Join(common, "index.lock")); err == nil {
			f.StateUnreadable = true
			f.Why = "index.lock present in the common dir (a concurrent git is mid-write)"
			f.Children = fileChildren(dir)
			return f
		}
	}
	out, err := r.run(dir, r.GitBudget, "status", "--porcelain", "--ignored")
	if err != nil {
		f.StateUnreadable = true
		f.Why = fmt.Sprintf("git status: %v", err)
		f.Children = fileChildren(dir)
		return f
	}
	f.parseStatus(dir, out, now)

	// rev-list decomposition: also repo-level when unreadable, EXCEPT the
	// unborn-HEAD repo (fresh `git init`, no commits yet): rev-list over
	// HEAD fails there, but that is not unreadable state  -  there is simply
	// nothing to push. `rev-parse --verify -q HEAD` exits NONZERO on an
	// unborn HEAD (the quiet missing-ref signal; pinned after the round-2
	// seat proved the exit-0-and-empty reading was dead code), and the
	// already-parsed dirty/untracked rows carry on and decide below.
	unborn := false
	if err := r.unpushed(dir, &f); err != nil {
		// `rev-parse --verify -q HEAD` exits NONZERO on an unborn HEAD. The
		// ONE typed predicate (quiet exit 1, empty stderr) decides unborn;
		// fatals (corrupt repo) and timeouts are NOT unborn  -  reading them
		// as such would zero unpushed counts on unreadable evidence, the
		// cardinal rule's edge (round-7: Facts kept a second, looser
		// heuristic long after the typed one landed).
		if uerr := func() error { _, e := r.run(dir, r.GitBudget, "rev-parse", "--verify", "-q", "HEAD"); return e }(); isQuietUnborn(uerr) {
			unborn = true
			f.Unpushed, f.ReflogOnly = 0, 0
		} else if uerr != nil {
			f.StateUnreadable = true
			f.Why = fmt.Sprintf("git rev-list: %v", err)
			f.Children = fileChildren(dir)
			return f
		} else {
			// The rev-parse probe SUCCEEDED (born HEAD): the unpushed
			// failure is real unreadable state.
			f.StateUnreadable = true
			f.Why = fmt.Sprintf("git rev-list: %v", err)
			f.Children = fileChildren(dir)
			return f
		}
	}

	// Everything below is fact-level: a failure weakens to FactsUnavailable.
	if out, err := r.run(dir, r.GitBudget, "stash", "list"); err == nil {
		f.Stashes = len(nonEmpty(out))
	} else {
		f.FactsUnavailable = true
		f.Why = fmt.Sprintf("git stash list: %v", err)
	}

	if out, err := r.run(dir, r.GitBudget, "remote"); err == nil {
		if len(nonEmpty(out)) == 0 {
			f.NoRemote = true
		}
	} else {
		f.FactsUnavailable = true
		f.Why = fmt.Sprintf("git remote: %v", err)
	}

	if out, err := r.run(dir, r.GitBudget, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		f.Branch = strings.TrimSpace(out)
	} else if !unborn {
		// On an unborn HEAD the branch probe fails with "ambiguous HEAD":
		// that is the unborn shape, not a tool failure, and marking it
		// FactsUnavailable would shadow the dirty/untracked rows that decide
		// (the end-to-end bug the engineering seat proved on pass three).
		f.FactsUnavailable = true
		f.Why = fmt.Sprintf("branch: %v", err)
	}
	if out, err := r.run(dir, r.GitBudget, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"); err == nil {
		f.Upstream = strings.TrimSpace(out)
	}
	if out, err := r.run(dir, r.GitBudget, "rev-parse", "HEAD"); err == nil {
		f.HEAD = strings.TrimSpace(firstLine(out))
	}
	if out, err := r.run(dir, r.GitBudget, "log", "-1", "--format=%cI"); err == nil {
		if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(firstLine(out))); err == nil {
			f.LastCommit = ts
		}
	}

	// Remote freshness: FETCH_HEAD lives in the COMMON dir, which a linked
	// worktree's per-worktree --git-path does not resolve for shared files,
	// so resolve the common dir directly (file-based, works even when the
	// repo is otherwise broken).
	if common, ok := gitCommonDir(dir); ok {
		if fi, err := os.Stat(filepath.Join(common, "FETCH_HEAD")); err == nil {
			f.LastFetch = fi.ModTime()
			f.RemoteStale = now.Sub(fi.ModTime()) > remoteStaleAfter
		} else {
			// No FETCH_HEAD: the stalest state there is (cloned but never
			// fetched, or the marker was pruned).
			f.RemoteStale = true
		}
	}

	f.Children = fileChildren(dir)
	return f
}

// FetchPrune runs git fetch --prune under the fetch budget (apply-time
// strengthening). An error means the caller demotes to remote-stale, never
// trusts the tracking refs it was about to use.
func (r Runner) FetchPrune(dir string) error {
	_, err := r.run(dir, r.FetchBudget, "fetch", "--prune")
	return err
}

// WorktreeRemove deregisters and deletes a linked worktree (apply path).
// Run FROM THE PARENT: `git -C <worktree> worktree remove <worktree>` makes
// the doomed worktree git's own cwd, so git deregisters it and then
// reliably fails to delete the tree (Windows refuses to remove a process's
// cwd)  -  the round-1 probe caught the apply path always falling through to
// rm believing deregistration failed.
func (r Runner) WorktreeRemove(dir string) error {
	return r.WorktreeRemoveFrom(dir, dir)
}

// WorktreeRemoveFrom runs the removal with cwd = the surviving parent.
func (r Runner) WorktreeRemoveFrom(dir, from string) error {
	_, err := r.run(from, r.GitBudget, "worktree", "remove", "--force", dir)
	return err
}

// WorktreePrune cleans stale registrations after rm-fallback deletions.
func (r Runner) WorktreePrune(dir string) error {
	_, err := r.run(dir, r.GitBudget, "worktree", "prune")
	return err
}

// RemoteURL returns origin's URL (or ""), used by the gh join.
func (r Runner) RemoteURL(dir string) string {
	out, err := r.run(dir, r.GitBudget, "remote", "get-url", "origin")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(firstLine(out))
}

// Remotes returns every configured remote name -> URL. The gh join matches
// PR head repositories against ALL of them: origin, upstream, a secondary
// fork  -  head repos vary by clone layout, and matching origin only is exactly
// the fork blind spot the spec closed.
func (r Runner) Remotes(dir string) map[string]string {
	out, err := r.run(dir, r.GitBudget, "remote", "-v")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, line := range nonEmpty(out) {
		// "name\turl (fetch)" / "name\turl (push)"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		m[fields[0]] = fields[1]
	}
	return m
}

// gitError carries the structured shape of a failed git call: exit code
// (when git exited), captured stderr, and whether it was a timeout. The
// unborn-HEAD discrimination (quiet exit 1 with empty stderr) keys on
// THESE fields, never on string suffixes of the formatted message.
type gitError struct {
	ExitCode int
	Stderr   string
	Timeout  bool
	msg      string
}

func (e *gitError) Error() string { return e.msg }

// isQuietUnborn is the ONE unborn-HEAD predicate, shared: git exited 1
// with nothing on stderr  -  `rev-parse --verify -q` on a missing HEAD.
// Fatals (corrupt repo, missing dir) and timeouts are NOT unborn.
func isQuietUnborn(err error) bool {
	ge, ok := err.(*gitError)
	return ok && !ge.Timeout && ge.ExitCode == 1 && ge.Stderr == ""
}

func (r Runner) run(dir string, budget time.Duration, args ...string) (string, error) {
	if budget <= 0 {
		return "", fmt.Errorf("no exec budget configured; refusing to run unbounded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir, "-c", "gc.auto=0"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// GIT_OPTIONAL_LOCKS=0: reap must never WRITE the index while reading.
	// git status opportunistically refreshes it, and reap's own write then
	// freshens the NEXT scan's walk-derived activity floor  -  a repo scanned
	// twice 20 seconds apart flipped SAFE to ACTIVE from exactly this. The
	// locked-index taxonomy is preserved structurally: Facts stats
	// index.lock before any exec, so a concurrent git mid-write still reads
	// StateUnreadable without reap having to take the lock to notice.
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", &gitError{Timeout: true, msg: fmt.Sprintf("timeout after %s", budget)}
	}
	if err != nil {
		ge := &gitError{Stderr: strings.TrimSpace(stderr.String()), msg: fmt.Sprintf("%v: %s", err, strings.TrimSpace(stderr.String()))}
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			ge.ExitCode = ee.ExitCode()
		}
		return "", ge
	}
	return stdout.String(), nil
}

// parseStatus splits porcelain --ignored output into the three counts and
// sizes the ignored entries (capped). The candidate's OWN .jj marker is
// excluded from the ignored count: jj writes .jj/.gitignore containing /*,
// so porcelain reports "!! .jj/" on every colocated repo, and counting the
// VCS's own marker would make clean-pushed structurally unreachable for the
// entire jj population. User artifacts under ignore rules still count.
func (f *Facts) parseStatus(dir, out string, now time.Time) {
	ignored := 0
	var ignoredPaths []string
	for _, line := range nonEmpty(out) {
		if len(line) < 4 {
			continue
		}
		xy, path := line[:2], line[3:]
		switch {
		case xy == "!!":
			p := trimQuotes(path)
			if p == ".jj" || p == ".jj/" {
				continue
			}
			ignored++
			if len(ignoredPaths) < ignoredBytesCap {
				ignoredPaths = append(ignoredPaths, p)
			}
		case strings.Contains(xy, "?"):
			f.Untracked++
		default:
			// Includes renames (R) and copies (C): one entry, one count.
			f.Dirty++
		}
	}
	f.Ignored = ignored
	if len(ignoredPaths) == ignored {
		// Under the cap: exact.
		for _, p := range ignoredPaths {
			f.IgnoredB += entrySize(dir, p, now)
		}
	} else if len(ignoredPaths) > 0 {
		f.IgnoredCap = true
		for _, p := range ignoredPaths {
			f.IgnoredB += entrySize(dir, p, now)
		}
	}
}

func entrySize(dir, rel string, now time.Time) int64 {
	p := filepath.Join(dir, filepath.FromSlash(rel))
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	if !fi.IsDir() {
		return fi.Size()
	}
	return walk.Entry(dir, p, now).Bytes
}

// unpushed decomposes local-only commits:
//
//	A = rev-list --all --reflog HEAD --not --remotes   (everything local-only)
//	B = rev-list --branches --tags HEAD --not --remotes (branch/tag/HEAD reachable)
//	Unpushed = |B|, ReflogOnly = |A \ B|.
//
// Reflog-only is the post-reset / pre-rebase residue: BLOCKED-class (it is
// real, recoverable work) but with an expiry date, because the house workflow
// (rebase, force-push, squash-merge, prune) manufactures it constantly and
// phantom forever-BLOCKED rows would train the user to distrust the screen.
func (r Runner) unpushed(dir string, f *Facts) error {
	all, err := r.revlistDates(dir, "--all", "--reflog", "HEAD")
	if err != nil {
		return err
	}
	// Branch-reachable includes the stash tip when one exists (refs/stash
	// is a ref like any other; leaving it out misfiles stashed commits as
	// reflog-only residue with a bogus expiry story). Probe first so
	// stash-less repos do not error on a missing ref.
	refs := []string{"--branches", "--tags", "HEAD"}
	if out, err := r.run(dir, r.GitBudget, "rev-parse", "--verify", "-q", "refs/stash"); err == nil && strings.TrimSpace(out) != "" {
		refs = append(refs, "refs/stash")
	}
	branchReach, err := r.revlistDates(dir, refs...)
	if err != nil {
		return err
	}
	f.Unpushed = len(branchReach)
	oldest := time.Time{}
	for sha, date := range all {
		if _, ok := branchReach[sha]; ok {
			continue
		}
		f.ReflogOnly++
		if oldest.IsZero() || date.Before(oldest) {
			oldest = date
		}
	}
	if f.ReflogOnly > 0 && !oldest.IsZero() {
		days := reflogExpiryDays - int(nowSince(oldest).Hours()/24)
		if days < 0 {
			days = 0
		}
		f.ExpireDays = days
	}
	return nil
}

// nowSince is a seam for tests; production uses time.Since.
var nowSince = time.Since

// revlistDates runs rev-list over the given positive refs and returns
// sha -> commit date for every local-only commit. Argument order matters:
// positive refs first, then "--not --remotes" last, because --not negates
// every ref that follows it (the reverse order would negate the positives too
// and quietly return nothing).
func (r Runner) revlistDates(dir string, refs ...string) (map[string]time.Time, error) {
	// refs/jj/** are jj's internal bookkeeping refs (move-tracking keeps
	// commits alive under refs/jj/keep indefinitely). Sweeping them with
	// --all mints phantom BLOCKED unpushed-reflog rows on every colocated
	// repo with zero user work  -  and because they are refs, not reflog
	// entries, the "expire in 90d" story is false forever (the conformance
	// seat's round-3 major). Excluded here in BOTH rev-lists of the
	// decomposition; --exclude must precede --all to apply.
	args := append([]string{"rev-list", "--exclude=refs/jj/*", "--pretty=format:%H %cI"}, refs...)
	args = append(args, "--not", "--remotes")
	out, err := r.run(dir, r.GitBudget, args...)
	if err != nil {
		return nil, err
	}
	m := map[string]time.Time{}
	for _, line := range nonEmpty(out) {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue // "commit <sha>" headers from the pretty machinery
		}
		sha, ts := fields[0], fields[1]
		if len(sha) < 7 || !isHex(sha) {
			continue
		}
		if date, err := time.Parse(time.RFC3339, ts); err == nil {
			m[sha] = date
		}
	}
	return m, nil
}

// fileChildren enumerates registered worktrees from the common dir WITHOUT
// exec: .git/worktrees/*/gitdir files name each worktree path, and this
// enumeration must survive a broken parent (that is the whole point of the
// parent-of-live-children check).
func fileChildren(dir string) []string {
	common, ok := gitCommonDir(dir)
	if !ok {
		return nil
	}
	// Children only for the repo ROOT: a linked worktree's own enumeration
	// (through the shared common dir) lists every SIBLING worktree of the
	// repo, and a sibling is not this dir's child  -  the mirrored wart of
	// jj's workspace list (the round-7 finding: two worktrees each counted
	// the other as a live child, wrong-reason MANUAL forever). The common
	// dir IS the root's .git; a candidate whose own gitdir sits elsewhere
	// is a worktree, not the root.
	if g, ok := gitDirFor(dir); !ok || filepath.Clean(g) != filepath.Clean(common) {
		return nil
	}
	wtsDir := filepath.Join(common, "worktrees")
	entries, err := os.ReadDir(wtsDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(wtsDir, e.Name(), "gitdir"))
		if err != nil {
			continue
		}
		// The gitdir file names <worktree>/.git with forward slashes and a
		// possibly 8.3-shortened prefix; Clean + LongPath normalize both so
		// children compare equal to the paths the user and reap scan.
		wtPath := strings.TrimSuffix(strings.TrimSpace(string(raw)), "/.git")
		wtPath = strings.TrimSuffix(wtPath, `\`+`.git`)
		wtPath = longPath(filepath.Clean(wtPath))
		if wtPath == "" {
			continue
		}
		// LIVE registered children only: a registration whose worktree dir
		// is gone (rm without prune) is stale metadata, not a child  -
		// counting it would pin the parent MANUAL parent-of-live-children
		// forever over a path nothing can act on. And the candidate itself
		// is never its own child (an only-child worktree listed itself and
		// displayed parent-of-live-children instead of its real row  -  the
		// round-2 finding).
		if _, err := os.Stat(wtPath); err != nil {
			continue
		}
		if config.Canonical(wtPath) == config.Canonical(dir) {
			continue
		}
		out = append(out, wtPath)
	}
	sort.Strings(out)
	return out
}

// gitDirFor resolves the candidate's OWN git dir: the linked worktree's
// per-worktree gitdir when .git is a file (index.lock lives THERE), else the
// root .git. Returns ok=false when no backend exists.
func gitDirFor(dir string) (string, bool) {
	gitPath := filepath.Join(dir, ".git")
	if fi, err := os.Stat(gitPath); err == nil && fi.IsDir() {
		return gitPath, true
	}
	raw, err := os.ReadFile(gitPath)
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "gitdir:")
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	s = filepath.FromSlash(s)
	if !filepath.IsAbs(s) {
		s = filepath.Join(dir, s)
	}
	return s, true
}

// gitCommonDir resolves the common git dir for a repo or linked worktree,
// reading the .git file rather than exec'ing, so a broken repo still yields
// its metadata paths.
func gitCommonDir(dir string) (string, bool) {
	gitPath := filepath.Join(dir, ".git")
	if fi, err := os.Stat(gitPath); err == nil && fi.IsDir() {
		return gitPath, true
	}
	raw, err := os.ReadFile(gitPath)
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "gitdir:")
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	s = filepath.FromSlash(s)
	if !filepath.IsAbs(s) {
		s = filepath.Join(dir, s)
	}
	// Linked worktree gitdir: .../repo/.git/worktrees/<n>; common dir is
	// .../repo/.git.
	if i := strings.Index(filepath.ToSlash(s), "/worktrees/"); i >= 0 {
		return filepath.FromSlash(filepath.ToSlash(s)[:i]), true
	}
	return s, true
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

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func isHex(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// Available reports whether git can be executed at all.
func Available() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// StatusSummary is the porcelain digest the quarantine manifest and the
// free-space preflight consume.
type StatusSummary struct {
	Dirty          int
	DirtyBytes     int64
	Untracked      int
	UntrackedBytes int64
	Ignored        int
	IgnoredBytes   int64
}

// StatusPorcelain returns the three-way split with per-class bytes. Dirty
// bytes are the full on-disk size of each modified file (an over-estimate
// of the staged delta  -  the safe direction for a free-space floor).
func (r Runner) StatusPorcelain(dir string) (StatusSummary, error) {
	var s StatusSummary
	out, err := r.run(dir, r.GitBudget, "status", "--porcelain", "--ignored")
	if err != nil {
		return s, err
	}
	for _, line := range nonEmpty(out) {
		if len(line) < 4 {
			continue
		}
		xy, p := line[:2], trimQuotes(line[3:])
		switch {
		case xy == "!!":
			if p == ".jj" || p == ".jj/" {
				continue
			}
			s.Ignored++
			s.IgnoredBytes += entrySize(dir, p, time.Now())
		case strings.Contains(xy, "?"):
			s.Untracked++
			s.UntrackedBytes += entrySize(dir, p, time.Now())
		default:
			s.Dirty++
			s.DirtyBytes += entrySize(dir, p, time.Now())
		}
	}
	return s, nil
}

// AddAll stages the entire working tree (quarantine capture step 1): the
// spec's pinned `git add -A -f .`, no exclusions  -  .jj is force-staged too
// (documented residue: op log / change-id mapping), because the capture
// must hold everything the working tree holds. The caller restores the
// index afterwards via RestoreBackup/ResetIndex.
func (r Runner) AddAll(dir string) error {
	_, err := r.run(dir, r.GitBudget, "add", "-A", "-f", ".")
	return err
}

// IndexLocked reports whether an index.lock exists in the worktree's own
// gitdir or the common dir (capture-start git-busy check; Facts checks the
// same files before any exec).
func (r Runner) IndexLocked(dir string) bool {
	if gi, ok := gitDirFor(dir); ok {
		if _, err := os.Stat(filepath.Join(gi, "index.lock")); err == nil {
			return true
		}
	}
	if common, ok := gitCommonDir(dir); ok {
		if _, err := os.Stat(filepath.Join(common, "index.lock")); err == nil {
			return true
		}
	}
	return false
}

// ResetIndex restores the index to HEAD after capture plumbing.
func (r Runner) ResetIndex(dir string) error {
	_, err := r.run(dir, r.GitBudget, "reset", "--mixed", "--quiet")
	return err
}

// WriteTree writes the staged index as a tree, returning its SHA.
func (r Runner) WriteTree(dir string) (string, error) {
	out, err := r.run(dir, r.GitBudget, "write-tree")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(firstLine(out)), nil
}

// CommitTree creates a commit object for tree (parent = HEAD when one
// exists), returning its SHA. Plumbing: no working-tree contact.
func (r Runner) CommitTree(dir, tree string) (string, error) {
	args := []string{"commit-tree", tree, "-m", "reap quarantine snapshot"}
	if head, err := r.run(dir, r.GitBudget, "rev-parse", "--verify", "-q", "HEAD"); err == nil && strings.TrimSpace(head) != "" {
		args = append(args, "-p", strings.TrimSpace(head))
	}
	out, err := r.run(dir, r.GitBudget, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(firstLine(out)), nil
}

// UpdateRef points ref at sha.
func (r Runner) UpdateRef(dir, ref, sha string) error {
	_, err := r.run(dir, r.GitBudget, "update-ref", ref, sha)
	return err
}

// LocalOnlyTip is one branch/tag tip not on any remote. Peeled is the
// commit SHA an annotated tag points AT (equal to SHA for lightweight tags
// and branches): membership tests against the unpushed COMMIt set must use
// Peeled  -  %(objectname) of an annotated tag is the tag OBJECT, which never
// appears in rev-list output, and comparing it silently skips every
// annotated-tag pin (the round-2 live data-loss probe).
type LocalOnlyTip struct {
	Ref    string
	SHA    string // the ref's own object (tag object for annotated tags)
	Peeled string // the commit it dereferences to ("" when it dereferences to nothing)
}

// LocalOnlyTips enumerates local branch and tag tips (the caller filters
// remote-reachable ones before pinning).
func (r Runner) LocalOnlyTips(dir string) ([]LocalOnlyTip, error) {
	out, err := r.run(dir, r.GitBudget, "for-each-ref", "--format=%(refname) %(objectname) %(*objectname)",
		"refs/heads", "refs/tags")
	if err != nil {
		return nil, err
	}
	var all []LocalOnlyTip
	for _, line := range nonEmpty(out) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		t := LocalOnlyTip{Ref: fields[0], SHA: fields[1]}
		if len(fields) >= 3 {
			t.Peeled = fields[2]
		}
		all = append(all, t)
	}
	return all, nil
}

// StashRefs returns every stash generation's SHA (oldest first; reflog-only
// objects a bare bundle would not carry). A stash-less repo is NOT an
// error: rev-list -g fails on a missing ref, so existence is probed first.
func (r Runner) StashRefs(dir string) ([]string, error) {
	if out, err := r.run(dir, r.GitBudget, "rev-parse", "--verify", "-q", "refs/stash"); err != nil || strings.TrimSpace(out) == "" {
		return nil, nil
	}
	out, err := r.run(dir, r.GitBudget, "rev-list", "-g", "refs/stash")
	if err != nil {
		return nil, err
	}
	return nonEmpty(out), nil
}

// UnpushedCommits returns the branch/tag/HEAD-reachable local-only commit
// set (one bounded rev-list  -  the same decomposition Facts runs, not a full
// --remotes enumeration, which materializes every remote-reachable SHA).
// pinTips marks a tip for pinning iff its SHA is in this set: a tip outside
// it is fully remote-reachable and recoverable by re-cloning.
func (r Runner) UnpushedCommits(dir string) map[string]bool {
	args := []string{"rev-list", "--exclude=refs/jj/*", "--branches", "--tags", "HEAD", "--not", "--remotes"}
	out, err := r.run(dir, r.GitBudget, args...)
	if err != nil {
		return nil
	}
	m := map[string]bool{}
	for _, sha := range nonEmpty(out) {
		m[sha] = true
	}
	return m
}

// ReflogOnlyCommits returns REFLOG ENTRY TIPS not reachable from any branch,
// tag or remote (post-reset / pre-rebase generations): the unpushed-reflog
// BLOCKED class. Entry tips, not the full rev-list enumeration: every commit
// reachable from an entry rides into the bundle under that entry's pin
// (<base>..<tip>), which bounds both the pin count and the command line  -
// a rev-list of a stale reflog-heavy repo mints thousands of refs and blows
// the Windows command-line bound (the round-2 reliability finding). Errors
// PROPAGATE: pinning nothing on unreadable evidence is the completeness lie
// the manifest must never tell  -  EXCEPT the unborn HEAD (fresh git init,
// no commits): `git reflog show HEAD` exits 128 there, but that is the
// unpushed-HEAD shape, not unreadable state, and quarantine must capture it
// fine (spec fixture list; the round-3 regression that broke exactly this).
func (r Runner) ReflogOnlyCommits(dir string) ([]string, error) {
	// The unborn probe must NOT swallow a timeout or a corrupt repo (the
	// round-4 completeness hole Facts guards). The ONE predicate  -  quiet
	// exit 1, empty stderr  -  is typed (gitError), never a string suffix:
	// a git killed by a signal with empty stderr must not read as unborn
	// (the round-6 engineering nit).
	if out, err := r.run(dir, r.GitBudget, "rev-parse", "--verify", "-q", "HEAD"); err != nil {
		if isQuietUnborn(err) {
			return nil, nil // unborn HEAD: no reflog to pin
		}
		return nil, err
	} else if strings.TrimSpace(out) == "" {
		return nil, nil
	}
	out, err := r.run(dir, r.GitBudget, "reflog", "show", "--format=%H", "HEAD")
	if err != nil {
		return nil, err
	}
	entries := nonEmpty(out)
	if len(entries) == 0 {
		return nil, nil
	}
	// Reachable-from-refs set, once (branches, tags, remotes).
	args := []string{"rev-list", "--exclude=refs/jj/*", "--branches", "--tags", "--remotes"}
	out, err = r.run(dir, r.GitBudget, args...)
	if err != nil {
		return nil, err
	}
	reachable := map[string]bool{}
	for _, sha := range nonEmpty(out) {
		reachable[sha] = true
	}
	var tips []string
	for _, sha := range entries {
		if !reachable[sha] {
			tips = append(tips, sha)
		}
	}
	return tips, nil
}

// ReflogEntryDates maps each HEAD reflog entry's commit to its commit date
// (RFC3339), for days-to-expiry reporting in the manifest.
func (r Runner) ReflogEntryDates(dir string) map[string]string {
	out, err := r.run(dir, r.GitBudget, "reflog", "show", "--format=%H %cI", "HEAD")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, line := range nonEmpty(out) {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			m[fields[0]] = fields[1]
		}
	}
	return m
}

// DiskUsage prices the objects the given rev-list ranges would carry
// (rev-list --disk-usage), so the caller can refuse BEFORE writing a bundle
// that would blow the cap or the volume.
func (r Runner) DiskUsage(dir string, ranges []string) (int64, error) {
	args := append([]string{"rev-list", "--disk-usage"}, ranges...)
	out, err := r.run(dir, r.GitBudget, args...)
	if err != nil {
		return 0, err
	}
	var n int64
	fmt.Sscanf(strings.TrimSpace(out), "%d", &n)
	return n, nil
}

// UpstreamRef resolves the current branch's upstream-tracking ref (empty
// when none). Base selection's first choice.
func (r Runner) UpstreamRef(dir string) string {
	out, err := r.run(dir, r.GitBudget, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(firstLine(out))
}

// ResolveRef returns the SHA a ref points at ("" when unresolvable): used
// to prove a candidate base exists before pricing ranges against it.
func (r Runner) ResolveRef(dir, ref string) string {
	out, err := r.run(dir, r.GitBudget, "rev-parse", "--verify", "-q", ref)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(firstLine(out))
}

// BranchUpstreams maps each local branch to its upstream ref when one is
// configured (the per-branch base union fallback).
func (r Runner) BranchUpstreams(dir string) map[string]string {
	out, err := r.run(dir, r.GitBudget, "for-each-ref", "--format=%(refname:short) %(upstream)", "refs/heads")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, line := range nonEmpty(out) {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] != "" {
			m[fields[0]] = fields[1]
		}
	}
	return m
}

// BundleCreateRanges writes a bundle from LITERAL range arguments (the
// spec's pinned form: the refs/reap/* set enumerated into an explicit
// <base>..<ref> list; a bare ref means a full, self-contained history).
func (r Runner) BundleCreateRanges(dir, dst string, ranges []string) error {
	args := append([]string{"bundle", "create", dst}, ranges...)
	_, err := r.run(dir, r.GitBudget, args...)
	return err
}

// LSRemote lists a remote's advertised refs ("sha ref" lines), read-only,
// under the fetch budget  -  the quarantine revalidation probe (one
// ls-remote per delta bundle).
func (r Runner) LSRemote(url string) (string, error) {
	return r.run(".", r.FetchBudget, "ls-remote", url)
}

// ForEachReapRef lists refs/reap/* pins in dir (nil on any failure  -  a
// non-repo simply has none): doctor's stranded-ref detector.
func (r Runner) ForEachReapRef(dir string) ([]string, error) {
	out, err := r.run(dir, r.GitBudget, "for-each-ref", "--format=%(refname)", "refs/reap")
	if err != nil {
		return nil, err
	}
	return nonEmpty(out), nil
}

// BundleVerify checks a bundle's integrity.
func (r Runner) BundleVerify(dir, bundle string) error {
	_, err := r.run(dir, r.GitBudget, "bundle", "verify", bundle)
	return err
}

// SaveIndex copies the index aside so capture can restore the operator's
// staged state exactly; empty return = nothing to save.
func (r Runner) SaveIndex(dir string) (string, error) {
	g, ok := gitDirFor(dir)
	if !ok {
		return "", fmt.Errorf("no git dir for %s", dir)
	}
	idx := filepath.Join(g, "index")
	data, err := os.ReadFile(idx)
	if err != nil {
		return "", nil
	}
	backup := idx + ".reap-backup"
	if err := os.WriteFile(backup, data, 0o644); err != nil {
		return "", err
	}
	return backup, nil
}

// RestoreBackup restores a SaveIndex backup atomically (temp + rename: a
// crash mid-write must not tear the live index) and removes the backup.
func (r Runner) RestoreBackup(dir, backup string) error {
	if backup == "" {
		return nil
	}
	g, ok := gitDirFor(dir)
	if !ok {
		return fmt.Errorf("no git dir for %s", dir)
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	tmp := filepath.Join(g, "index.reap-restore")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(g, "index")); err != nil {
		return err
	}
	return os.Remove(backup)
}
