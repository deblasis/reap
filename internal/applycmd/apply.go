// Package applycmd implements `reap plan` and `reap apply`: the deletion
// pipeline. The spec's choreography, in order: print the plan (naming
// widened codes and counts), preflight free space, require TTY-confirm or
// --yes (never infer from EOF; 121 when non-interactive without --yes),
// take apply.lock, then per path — re-verify the verdict seconds before
// deletion with cache-bypassed fresh facts (fetch --prune under its own
// budget, fresh walk tripwire, rename in-use probe), skip and log anything
// that changed, delete children before parents, contents before .git/.jj,
// deregister before removal, write the audit trail ahead of every deletion,
// and end with the deleted/excluded/skipped summary and exit band.
package applycmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/auditlog"
	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/jjx"
	"github.com/deblasis/reap/internal/lockfile"
	"github.com/deblasis/reap/internal/verdict"
	"github.com/deblasis/reap/internal/walk"
)

// Exit band (spec): 0 fully executed; 2 executed with skips; 120 usage;
// 121 not interactive; 122 config/state/lock; 123 root missing; 124
// deletion failed (path named).
const (
	ExitOK          = 0
	ExitWithSkips   = 2
	ExitUsage       = 120
	ExitNotTTY      = 121
	ExitState       = 122
	ExitRootMissing = 123
	ExitDeleteFail  = 124
)

// skipWhy values (spec's closed enum).
const (
	SkipGitBusy        = "git-busy"
	SkipActiveTripwire = "active-tripwire"
	SkipInUseProbe     = "in-use-probe"
	SkipVerdictChanged = "verdict-changed"
	SkipParentLive     = "parent-of-live-children"
	SkipIgnorance      = "ignorance-unreadable"
)

// PlanEntry is one path the plan proposes to delete.
type PlanEntry struct {
	Path      string
	Verdict   string // SAFE, or MANUAL via widening/override
	Code      string
	SizeBytes int64
	Widened   bool
	Kind      classify.Kind
	Parent    string // classify-resolved parent repo (lineage ordering)
}

// Options carries the shared scan-shaping flags (scan, plan, apply accept
// the same set, so the reviewed view and the executed set cannot differ).
type Options struct {
	Roots            []string
	MinGB            float64
	NoGH, NoJJ       bool
	Include, Exclude []string
	OverrideManual   []string
	JSON             bool
	Yes              bool
	DryRun           bool
}

// Summary is the run's end state (the --json body for apply, and the
// printed summary's source).
type Summary struct {
	RunID    string        `json:"runId"`
	Planned  []string      `json:"planned"`
	Widened  []string      `json:"widened"`
	Deleted  []string      `json:"deleted"`
	Skipped  []SkippedPath `json:"skipped"`
	Excluded []string      `json:"excluded"`
	FreeGain uint64        `json:"freeBytesReclaimed"`
}

// SkippedPath names why a planned path survived.
type SkippedPath struct {
	Path string `json:"path"`
	Why  string `json:"why"`
}

// Deleter is the fact-collection seam the re-verify uses. cmdScan's shared
// core fills it; tests inject fixed facts.
type Deleter struct {
	Git gitx.Runner
	JJ  jjx.Runner
}

// IsTerminal reports whether w is an interactive TTY. Windows ConHost and
// modern terminals report true for console handles only.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return isTerminalFd(f)
}

// Confirm prints the plan and asks. Returns (proceed, exitCode).
func Confirm(out io.Writer, in *os.File, plan []PlanEntry, widened int, minFree uint64, free uint64, opts Options) (bool, int) {
	var totalBytes int64
	for _, p := range plan {
		totalBytes += p.SizeBytes
	}
	fmt.Fprintf(out, "reap will permanently delete %d directories, %.1f GB logical (not recycled)", len(plan), float64(totalBytes)/(1<<30))
	if widened > 0 {
		fmt.Fprintf(out, "; %d widened via --include", widened)
	}
	fmt.Fprintln(out)
	if minFree > 0 {
		fmt.Fprintf(out, "preflight: %d MB free required, %d MB free\n", minFree/(1<<20), free/(1<<20))
	}
	if opts.DryRun {
		fmt.Fprintln(out, "dry-run: nothing will be deleted")
		return false, ExitOK
	}
	if !opts.Yes {
		if !IsTerminal(out) {
			fmt.Fprintln(out, "reap apply deletes permanently; pass --yes to confirm when not interactive")
			return false, ExitNotTTY
		}
		fmt.Fprint(out, "Proceed? [y/N] ")
		var answer string
		if _, err := fmt.Fscanln(in, &answer); err != nil {
			// Enter/EOF declines: confirmation is NEVER inferred from EOF.
			fmt.Fprintln(out, "\ndeclined")
			return false, ExitOK
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fmt.Fprintln(out, "declined")
			return false, ExitOK
		}
	}
	return true, ExitOK
}

// OrderChildrenFirst sorts the plan so lineage children (worktrees, jj
// workspaces) delete before their parents, and a parent whose live children
// outside the set exist is dropped from the plan (with a skip entry) — the
// spec's parent-of-live-children unlock rule.
func OrderChildrenFirst(plan []PlanEntry) ([]PlanEntry, []SkippedPath) {
	inSet := map[string]bool{}
	byParent := map[string][]PlanEntry{}
	var roots, out []PlanEntry
	for _, p := range plan {
		inSet[config.Canonical(p.Path)] = true
	}
	var skips []SkippedPath
	for _, p := range plan {
		if p.Parent != "" && config.Canonical(p.Parent) != config.Canonical(p.Path) && inSet[config.Canonical(p.Parent)] {
			byParent[config.Canonical(p.Parent)] = append(byParent[config.Canonical(p.Parent)], p)
		} else {
			roots = append(roots, p)
		}
	}
	// Children first: every entry whose parent is in the set goes before
	// that parent. Depth is at most two in practice (workspace -> repo).
	for _, parent := range roots {
		out = append(out, byParent[config.Canonical(parent.Path)]...)
		out = append(out, parent)
	}
	return out, skips
}

// Reverify re-runs the deletion-time checks for one path: cache-bypassed
// fresh walk (tripwire), fresh git facts with fetch --prune, the rename
// in-use probe. Returns a skipWhy ("" = proceed) and the fresh verdict for
// the audit intent line.
func Reverify(path string, opts Options, cfg config.Config, d Deleter, protectExpanded []string, holds map[string]bool) (skipWhy string, fresh verdict.Verdict) {
	now := time.Now()
	remoteStale := time.Duration(cfg.Thresholds.RemoteStaleHours) * time.Hour

	// Heal strays first (never overwrite: a stranded probe name with a live
	// original parks as .reap-orphaned-<ts> and is surfaced, not merged).
	HealProbingStrays(filepath.Dir(path))

	// Fresh walk: lastActivity NEVER from cache (the spec's structural rule).
	info := walk.Entry(filepath.Dir(path), path, now)
	if info.Partial {
		return SkipIgnorance, verdict.Verdict{Verdict: verdict.Manual, Code: "state-unreadable"}
	}
	if now.Sub(info.MaxMtime) < 2*time.Hour {
		return SkipActiveTripwire, verdict.Verdict{Verdict: verdict.Active, Code: "active"}
	}

	classInfo := classify.Dir(path)
	in := verdict.Input{
		Path: path, Kind: classInfo.Kind, SizeBytes: info.Bytes,
		LastActivity: info.MaxMtime, NestedVCS: info.NestedVCS,
		GitBackend: classInfo.GitBackend, Thresholds: cfg.Thresholds, Now: now,
		Held:      heldUnder(holds, path),
		Protected: protected(path, protectExpanded),
	}
	if classInfo.GitBackend || (classInfo.Kind == classify.KindGitWorktreeOrphaned && classInfo.ParentRepo != "") {
		// Apply-time strengthening: prune stale remote-tracking refs before
		// computing unpushed (offline/timeout -> remote-stale MANUAL, never
		// trust of stale refs).
		if err := d.Git.FetchPrune(path); err != nil {
			f := gitx.Facts{StateUnreadable: true, Why: fmt.Sprintf("fetch --prune: %v", err)}
			in.Git = &f
		} else {
			f := d.Git.Facts(path, now, remoteStale)
			in.Git = &f
		}
	}
	if classInfo.Kind == classify.KindJJRepo || classInfo.Kind == classify.KindJJWorkspace {
		f := d.JJ.Facts(path, now, remoteStale)
		in.JJ = &f
	}
	v := verdict.Decide(in)

	// BLOCKED-class or ignorance: never deletable by re-verify.
	if v.BlockedClassFact != "" && !v.OrphanedCarveOut {
		return SkipVerdictChanged, v
	}
	switch v.Verdict {
	case verdict.Safe:
		// proceed
	case verdict.Manual:
		// Widened/overridden judgment rows only; check the caller included
		// this path (the caller filters by code; ignorance rows skip).
		if _, ign := map[string]bool{
			"facts-unavailable": true, "state-unreadable": true, "remote-stale": true,
			"jj-remote-stale": true, "gh-unavailable": true, "unknown-kind": true,
		}[v.Code]; ign {
			return SkipIgnorance, v
		}
	default: // ACTIVE / KEEP / BLOCKED displayed
		if v.Verdict == verdict.Blocked {
			return SkipVerdictChanged, v
		}
		return SkipVerdictChanged, v
	}

	// Rename in-use probe: deterministic sibling, \\?\ long-safe paths,
	// restore retried; a restore failure is a hard error the caller turns
	// into an abort naming the new path.
	if err := renameProbe(path); err != nil {
		if errors.Is(err, errProbeInUse) {
			return SkipInUseProbe, v
		}
		// Restore failed: the dir is stranded under the probe name. This is
		// a hard abort, not a skip: surface it loudly.
		return "PROBE-STRANDED:" + err.Error(), v
	}
	return "", v
}

var errProbeInUse = errors.New("dir is in use (rename refused)")

func longPath(p string) string {
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	return `\\?\` + p
}

func renameProbe(path string) error {
	dir, name := filepath.Split(path)
	if name == "" {
		dir, name = filepath.Split(strings.TrimRight(path, string(os.PathSeparator)))
	}
	probe := filepath.Join(dir, name+".reap-probing")
	_ = os.Remove(longPath(probe)) // stale probe with no live original: healable leftover
	if err := os.Rename(longPath(path), longPath(probe)); err != nil {
		return errProbeInUse
	}
	backErr := os.Rename(longPath(probe), longPath(path))
	for i := 0; i < 2 && backErr != nil; i++ {
		time.Sleep(50 * time.Millisecond)
		backErr = os.Rename(longPath(probe), longPath(path))
	}
	if backErr != nil {
		return fmt.Errorf("RESTORE FAILED: dir stranded at %s: %w", probe, backErr)
	}
	return nil
}

// HealProbingStrands heals .reap-probing leftovers in dir: original absent ->
// rename back; both present -> park the stray as .reap-orphaned-<ts>.
func HealProbingStrays(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".reap-probing") {
			continue
		}
		stray := filepath.Join(dir, name)
		orig := filepath.Join(dir, strings.TrimSuffix(name, ".reap-probing"))
		if _, err := os.Stat(longPath(orig)); os.IsNotExist(err) {
			_ = os.Rename(longPath(stray), longPath(orig))
			continue
		}
		parked := filepath.Join(dir, name+".reap-orphaned-"+time.Now().Format("150405"))
		_ = os.Rename(longPath(stray), longPath(parked))
	}
}

// Delete removes one path: deregister first (worktree remove / jj workspace
// forget), then rm with contents-before-.git/.jj ordering, with the audit
// write-ahead bracketing. mode names how it went for the result line.
func Delete(path string, classInfo classify.Info, d Deleter, log *auditlog.Log, intent auditlog.Line) (mode string, err error) {
	mode = "rm"
	if classInfo.Kind == classify.KindGitWorktree && classInfo.ParentRepo != "" {
		if err := d.Git.WorktreeRemove(path); err == nil {
			mode = "worktree-remove"
			ok := true
			intent.Mode = mode
			intent.OK = &ok
			_ = log.Append(intent) // result semantics: full removal below skipped
			return mode, nil
		}
		// fall through to rm + prune later
	}
	if (classInfo.Kind == classify.KindJJWorkspace || classInfo.Kind == classify.KindJJRepo) && classInfo.ParentRepo != "" {
		if err := d.JJ.WorkspaceForget(classInfo.ParentRepo, filepath.Base(path)); err == nil {
			mode = "jj-forget+rm"
		}
		// forget failure does NOT block: the working copy removal is the
		// point; the parent's stale registration is healed by `jj` later or
		// surfaced by scan (children existence-checked).
	}
	if err := removeContentsBeforeVCS(path); err != nil {
		return mode, err
	}
	return mode, nil
}

// removeContentsBeforeVCS deletes everything except the VCS metadata first,
// then the metadata: a partial failure preserves history and reflog — the
// difference between "lost work" and "an undeletable husk".
func removeContentsBeforeVCS(path string) error {
	lp := longPath(path)
	entries, err := os.ReadDir(lp)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == ".git" || e.Name() == ".jj" {
			continue
		}
		if err := os.RemoveAll(longPath(filepath.Join(path, e.Name()))); err != nil {
			return err
		}
	}
	return os.RemoveAll(lp)
}

// Lock takes apply.lock exclusively; a held lock fails fast naming the
// holder PID.
func Lock(stateDir string) (*lockfile.File, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, err
	}
	l, err := lockfile.Open(filepath.Join(stateDir, "apply.lock"))
	if err != nil {
		return nil, err
	}
	ok, err := l.TryLock()
	if err != nil {
		return nil, err
	}
	if !ok {
		l.Close()
		return nil, fmt.Errorf("another reap apply/discard holds apply.lock (fail-fast; retry when it exits)")
	}
	return l, nil
}

// ReadHoldsSnapshot is the shared lenient read for display commands.
func ReadHoldsSnapshot(stateDir string) map[string]time.Time {
	raw, err := os.ReadFile(filepath.Join(stateDir, "holds.json"))
	if err != nil {
		return nil
	}
	var hf map[string]struct {
		Expires time.Time `json:"expires"`
	}
	if json.Unmarshal(raw, &hf) != nil {
		return nil
	}
	out := map[string]time.Time{}
	for p, h := range hf {
		out[config.Canonical(p)] = h.Expires
	}
	return out
}

func heldUnder(holds map[string]bool, path string) bool {
	if len(holds) == 0 {
		return false
	}
	pc := config.Canonical(path)
	// walk up component by component
	parts := strings.Split(pc, string(os.PathSeparator))
	for i := len(parts); i >= 1; i-- {
		if holds[strings.Join(parts[:i], string(os.PathSeparator))] {
			return true
		}
	}
	return false
}

func protected(path string, globs []string) bool {
	ok, _ := config.MatchProtect(path, globs)
	return ok
}
