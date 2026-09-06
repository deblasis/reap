// Package verdict applies the design spec's matrix to one candidate's facts.
//
// Two invariants govern everything (spec v7):
//
//  1. No path to SAFE on stale, missing, or errored evidence: every failure
//     flag, staleness signal, and unreadable state lands MANUAL before any
//     clean row can fire.
//  2. Deletion reachability is computed from the FULL fact set, never the
//     displayed row: BlockedClassFact is set whenever any BLOCKED-class fact
//     exists, so --include/--override-manual gating cannot be fooled by a
//     more-specific MANUAL row shadowing it (the nested-clone-is-untracked
//     class of bug).
package verdict

import (
	"fmt"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/ghx"
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/jjx"
)

// Verdict values.
const (
	Safe    = "SAFE"
	Blocked = "BLOCKED"
	Manual  = "MANUAL"
	Active  = "ACTIVE"
	Keep    = "KEEP"
)

// Ignorance-class codes: overriding unread (or unclassifiable) state is a
// side door around invariant 1, so these are never override-eligible.
var ignoranceClass = map[string]bool{
	"facts-unavailable": true,
	"state-unreadable":  true,
	"remote-stale":      true,
	"jj-remote-stale":   true,
	"gh-unavailable":    true,
	"unknown-kind":      true,
}

// Judgment-class codes: human-judgment MANUALs, override-eligible once the
// full-fact gate passes.
var judgmentClass = map[string]bool{
	"ignored-content":         true,
	"orphaned-worktree":       true,
	"orphaned-workspace":      true,
	"nested-repositories":     true,
	"parent-of-live-children": true,
	"scratch-recent":          true,
}

// Input carries every fact the matrix consumes. Nil optionals mean "not
// applicable", never "checked and clean": applicable-but-nil facts are
// routed to facts-unavailable by Decide, and the classifier's kinds make
// applicability explicit.
type Input struct {
	Path       string
	Kind       classify.Kind
	ParentRepo string

	SizeBytes    int64
	SizePartial  bool
	LastActivity time.Time
	NestedVCS    []string
	IsReparse    bool

	Git         *gitx.Facts  // required for git kinds
	JJ          *jjx.Facts   // required for jj kinds (colocated repos have both)
	PRHeads     *ghx.PRHeads // nil = gh unavailable this run
	RemoteSlugs []string     // slugs of ALL configured remotes (any-remote join)

	Held      bool
	Protected bool

	// GitBackend mirrors classify.Info.GitBackend: a jj repo may or may not
	// carry a git backend (colocated vs split-layout), and only the kind+backend
	// pair says whether git facts are REQUIRED. A backend-less jj repo with
	// nil Git is deciding on jj facts, not missing evidence.
	GitBackend bool

	IncodaLive bool // live incoda ticket at/under the dir (M4 attribution)

	Thresholds config.Thresholds
	Now        time.Time
}

// Verdict is the decision plus everything downstream (plan, apply, report)
// needs: the machine-stable reasonCode, human prose, a full-fact-set hint
// that never advertises a gate the tool will refuse, and the reachability
// classification. OpenPRSlug/OpenPRBranch carry the matched join so callers
// never re-implement it (a duplicated join drifted once already).
type Verdict struct {
	Verdict string
	Code    string
	Reason  string
	Hint    string

	OpenPRSlug   string
	OpenPRBranch string

	// BlockedClassFact is non-empty when any BLOCKED-class fact is present,
	// regardless of which row displayed. The one exception is the orphaned
	// carve-out, flagged separately: orphaned kinds can never push and never
	// become readable, so their facts gate a hardened confirm instead of a
	// refusal.
	BlockedClassFact string
	OrphanedCarveOut bool
}

// Decide applies the matrix. Row order is the spec's and is load-bearing:
// KEEP rails first; orphan detection (file-based, structural) outranks
// unreadable-state rows; every failure row outranks every clean row;
// BLOCKED-class rows outrank SAFE so shadowing can only ever DISPLAY a
// weaker row, never reach one.
func Decide(in Input) Verdict {
	v := Verdict{Verdict: Manual}

	// BLOCKED-class fact scan first: reachability comes from the full fact
	// set, computed before any row is chosen.
	v.BlockedClassFact = blockedClassFact(in)

	switch {
	case in.Held:
		return keep("held-by-user", "held by user", "reap unhold to release")
	case in.Protected:
		return keep("protected", "protected path", "config.json protect list")
	case in.IsReparse:
		// A junction/symlink candidate is the link, not the target: facts
		// harvested through it are evidence about a DIFFERENT path, and the
		// walk never ran, so activity and size are zero-value sentinels.
		return keep("protected", "reparse point (junction/symlink)", "candidate itself is a link; not deletable")
	case in.IncodaLive:
		return v.set(Active, "incoda-live", "live incoda ticket", "")
	}

	active := in.activeHours()
	if !in.LastActivity.IsZero() && in.Now.Sub(in.LastActivity) < active {
		return v.set(Active, "active", fmt.Sprintf("active (<%dh)", int(active.Hours())), "")
	}

	switch in.Kind {
	case classify.KindGitWorktreeOrphaned:
		v.OrphanedCarveOut = true
		return v.set(Manual, "orphaned-worktree", "orphaned worktree, files may be only copy",
			"orphaned: parent gone; reap apply --override-manual asks a TTY-only hardened confirm")
	case classify.KindJJWorkspaceOrphaned:
		v.OrphanedCarveOut = true
		return v.set(Manual, "orphaned-workspace", "orphaned jj workspace, files may be only copy",
			"orphaned: parent gone; reap apply --override-manual asks a TTY-only hardened confirm")
	}

	if in.Git != nil && in.Git.StateUnreadable {
		return v.set(Manual, "state-unreadable",
			"repo state unreadable ("+shortWhy(in.Git.Why)+")",
			"fix the repo state (locked index? corrupt .git?), rerun scan")
	}
	// Partial walk ranks with the other unreadable-state rows, ABOVE the
	// judgment rows: a size that is only a lower bound must not display a
	// judgment row whose hint advertises --override-manual over unread
	// evidence.
	if in.SizePartial {
		return v.set(Manual, "state-unreadable", "size walk incomplete (lower bound)",
			"rerun scan; a path was unreadable under this dir")
	}

	// Applicable-but-nil facts degrade to ignorance, never vacuous
	// cleanliness: --no-jj (or jj missing) on a jj kind must not let the
	// clean rows read the jj side as clean by omission. Mirrors the gh
	// treatment (nil PRHeads -> gh-unavailable).
	if kindNeedsGit(in.Kind, in.GitBackend) && in.Git == nil {
		return v.set(Manual, "facts-unavailable",
			"git facts unavailable (git missing or disabled)",
			"install git, or rerun with the git phase enabled")
	}
	if kindNeedsJJ(in.Kind) && in.JJ == nil {
		return v.set(Manual, "facts-unavailable",
			"jj facts unavailable (jj missing or disabled)",
			"install jj, or rerun without --no-jj")
	}

	// Tool-level failures across every fact source.
	if why := factsUnavailableWhy(in); why != "" {
		return v.set(Manual, "facts-unavailable", "facts unavailable ("+why+")",
			"rerun scan, check tool health ("+why+")")
	}

	switch in.Kind {
	case classify.KindUnknown:
		return v.set(Manual, "unknown-kind", "could not classify",
			"inspect manually; no VCS markers and not a plain scratch dir")
	}

	if len(in.NestedVCS) > 0 {
		return v.set(Manual, "nested-repositories",
			fmt.Sprintf("nested repo(s): %d", len(in.NestedVCS)),
			"resolve the nested repo first, then --override-manual")
	}

	if n := liveChildren(in); n > 0 {
		return v.set(Manual, "parent-of-live-children",
			fmt.Sprintf("live child worktrees/workspaces: %d", n),
			"delete the children in the same run to unlock this parent")
	}

	if in.Git != nil {
		switch {
		case in.Git.Dirty > 0 || in.Git.Untracked > 0:
			// The row covers tracked-modified AND untracked content: the spec
			// detail format carries both counts, and untracked-only content
			// is exactly the "agent parked files here" case the row exists
			// for.
			return v.set(Blocked, "dirty-files",
				fmt.Sprintf("%d tracked-modified, %d untracked", in.Git.Dirty, in.Git.Untracked),
				"commit+push the work")
		case in.Git.Stashes > 0:
			return v.set(Blocked, "stashes", fmt.Sprintf("%d stashes", in.Git.Stashes),
				"push or pop the stash")
		}
		if in.Git.Ignored > 0 {
			gb := float64(in.Git.IgnoredB) / (1 << 30)
			unit := "GB"
			if gb < 1 {
				gb = float64(in.Git.IgnoredB) / (1 << 20)
				unit = "MB"
			}
			capped := ""
			if in.Git.IgnoredCap {
				capped = "+"
			}
			return v.set(Manual, "ignored-content",
				fmt.Sprintf("ignored content: %d files, %.1f%s %s", in.Git.Ignored, gb, capped, unit),
				"review the ignored files, then --override-manual")
		}
		if in.Git.Unpushed > 0 {
			return v.set(Blocked, "unpushed-commits",
				fmt.Sprintf("%d unpushed commits", in.Git.Unpushed),
				fmt.Sprintf("push origin %s", branchOr(in, "HEAD")))
		}
		if in.Git.ReflogOnly > 0 {
			return v.set(Blocked, "unpushed-reflog",
				fmt.Sprintf("%d reflog-only commits, expire in %dd; pushing clears nothing", in.Git.ReflogOnly, in.Git.ExpireDays),
				fmt.Sprintf("reflog residue: expires in %dd; wait it out", in.Git.ExpireDays))
		}
		if in.Git.NoRemote {
			return v.set(Blocked, "no-remote",
				"no remote configured, work exists only here",
				"add a remote or bundle the work")
		}
		if in.Git.RemoteStale {
			return v.set(Manual, "remote-stale",
				"remote state stale, fetch needed",
				"git fetch, rerun scan")
		}
		// The open-PR row doubles as the gh-unavailable row: an unavailable
		// PR set must never read as "no open PRs".
		if in.PRHeads == nil || in.PRHeads.Unavailable {
			return v.set(Manual, "gh-unavailable", "gh unavailable; open-PR state unknown",
				"check gh auth, rerun scan")
		}
		if slug, branch := in.openPR(); slug != "" {
			v.OpenPRSlug, v.OpenPRBranch = slug, branch
			return v.set(Blocked, "open-pr",
				fmt.Sprintf("open PR uses branch %s (%s)", branch, slug),
				"PR is open; keep until merged or closed")
		}
	}

	if in.JJ != nil {
		if in.JJ.Unavailable {
			return v.set(Manual, "facts-unavailable",
				"jj facts unavailable ("+shortWhy(in.JJ.Why)+")",
				"fix jj (installed? repo readable?), rerun scan")
		}
		if in.JJ.UnpushedChanges > 0 {
			return v.set(Blocked, "jj-unpushed",
				fmt.Sprintf("%d jj changes not on any remote", in.JJ.UnpushedChanges),
				"jj git push the work")
		}
		if in.JJ.RemoteStale {
			return v.set(Manual, "jj-remote-stale", "jj remote bookmarks stale",
				"jj git fetch, rerun scan")
		}
		if !in.JJ.LastOp.IsZero() && in.Now.Sub(in.JJ.LastOp) < active {
			return v.set(Active, "jj-active", "jj activity (<active window)", "")
		}
	}

	// The clean rows. SAFE requires EVERYTHING clean, per kind applicability:
	// git facts for git kinds, jj facts for jj kinds, and nothing shadowed.
	// A scratch dir has no VCS facts at all, so cleanAndPushed must not fire
	// for it — vacuous cleanliness is not cleanliness (the scratch tiers own
	// that decision, from walk-derived activity).
	if (in.Git != nil || in.JJ != nil) && cleanAndPushed(in) {
		return v.set(Safe, "clean-pushed", "clean + fully pushed", "reap plan, then reap apply")
	}

	// Scratch tiers: lastActivity is walk-derived (never cached).
	if in.Kind == classify.KindScratch {
		days := int(in.Now.Sub(in.LastActivity).Hours() / 24)
		switch {
		case days >= in.Thresholds.ScratchSafeDays:
			return v.set(Safe, "scratch-idle",
				fmt.Sprintf("scratch idle %d days", days),
				"nothing protects this; reap plan includes it")
		case days >= in.Thresholds.ScratchManualDays:
			return v.set(Manual, "scratch-recent",
				fmt.Sprintf("scratch idle %d days (7-21)", days),
				"wait, or widen with --include scratch-recent")
		default:
			return v.set(Active, "scratch-fresh",
				fmt.Sprintf("fresh scratch (%d days)", days), "")
		}
	}

	// No row matched: that is undefined by the matrix and must never leak a
	// default SAFE. Matrix-completeness tests make this unreachable; keeping
	// it MANUAL here is the fail-safe.
	return v.set(Manual, "unknown-kind", "no matrix row matched (internal; report as bug)",
		"report this: a fixture should have matched a row")
}

func (v *Verdict) set(verdict, code, reason, hint string) Verdict {
	v.Verdict = verdict
	v.Code = code
	v.Reason = reason
	v.Hint = hint
	// Shadow-aware hints: a judgment row that shadows a BLOCKED-class fact
	// must not advertise the override as if it were unblocked. The orphaned
	// carve-out is the exception — its BLOCKED facts do NOT gate the
	// override (the hardened confirm does), so "resolve that first" would
	// advertise an ordering the tool will not enforce.
	if v.BlockedClassFact != "" && v.Verdict == Manual && judgmentClass[code] && hint != "" {
		if v.OrphanedCarveOut {
			v.Hint = "also: " + v.BlockedClassFact + "; " + hint
		} else {
			v.Hint = "also: " + v.BlockedClassFact + "; resolve that first, then " + hint
		}
	}
	return *v
}

func keep(code, reason, hint string) Verdict {
	return Verdict{Verdict: Keep, Code: code, Reason: reason, Hint: hint}
}

// blockedClassFact scans the FULL fact set for anything BLOCKED-class,
// independent of which row will display.
func blockedClassFact(in Input) string {
	if in.Git != nil && !in.Git.StateUnreadable {
		switch {
		case in.Git.Dirty > 0 || in.Git.Untracked > 0:
			return fmt.Sprintf("%d dirty/untracked files", in.Git.Dirty+in.Git.Untracked)
		case in.Git.Stashes > 0:
			return fmt.Sprintf("%d stashes", in.Git.Stashes)
		case in.Git.Unpushed > 0:
			return fmt.Sprintf("%d unpushed commits", in.Git.Unpushed)
		case in.Git.ReflogOnly > 0:
			return fmt.Sprintf("%d reflog-only commits", in.Git.ReflogOnly)
		case in.Git.NoRemote:
			return "no remote configured"
		}
	}
	if in.JJ != nil && !in.JJ.Unavailable && in.JJ.UnpushedChanges > 0 {
		return fmt.Sprintf("%d unpushed jj changes", in.JJ.UnpushedChanges)
	}
	// The open-PR fact is BLOCKED-class when positively held (a slug match),
	// never when gh is merely unavailable.
	if in.PRHeads != nil && !in.PRHeads.Unavailable {
		if slug, branch := in.openPR(); slug != "" {
			return fmt.Sprintf("open PR on %s (%s)", branch, slug)
		}
	}
	return ""
}

// cleanAndPushed is the SAFE row's full condition.
func cleanAndPushed(in Input) bool {
	if len(in.NestedVCS) > 0 || liveChildren(in) > 0 || in.SizePartial {
		return false
	}
	if in.Git != nil {
		if in.Git.StateUnreadable || in.Git.FactsUnavailable {
			return false
		}
		if in.Git.Dirty > 0 || in.Git.Untracked > 0 || in.Git.Ignored > 0 ||
			in.Git.Stashes > 0 || in.Git.Unpushed > 0 || in.Git.ReflogOnly > 0 ||
			in.Git.NoRemote || in.Git.RemoteStale {
			return false
		}
		if in.PRHeads == nil || in.PRHeads.Unavailable {
			return false
		}
		if slug, _ := in.openPR(); slug != "" {
			return false
		}
	}
	if in.JJ != nil {
		if in.JJ.Unavailable || in.JJ.UnpushedChanges > 0 || in.JJ.RemoteStale {
			return false
		}
		if !in.JJ.LastOp.IsZero() && in.Now.Sub(in.JJ.LastOp) < in.activeHours() {
			return false
		}
	}
	return true
}

// openPR evaluates the any-remote join: PR head slug matches ANY configured
// remote slug and the head branch equals the current (or upstream-tracking)
// branch.
func (in Input) openPR() (slug, branch string) {
	if in.PRHeads == nil || in.PRHeads.Unavailable || in.Git == nil {
		return "", ""
	}
	branch = in.Git.Branch
	if branch == "" || branch == "HEAD" {
		if u := in.Git.Upstream; u != "" {
			if i := strings.LastIndexByte(u, '/'); i >= 0 {
				branch = u[i+1:]
			}
		}
	}
	if branch == "" || branch == "HEAD" {
		return "", ""
	}
	for _, s := range in.RemoteSlugs {
		if in.PRHeads.Holds(s, branch) {
			return s, branch
		}
	}
	return "", ""
}

func liveChildren(in Input) int {
	n := 0
	if in.Git != nil {
		n += len(in.Git.Children)
	}
	if in.JJ != nil {
		n += len(in.JJ.Children)
	}
	return n
}

// kindNeedsGit reports whether a kind's verdict requires git facts. A nil Git
// where facts are required is unavailable evidence (git missing, disabled),
// never "checked and clean". Split-layout jj repos (jj kind, no backend)
// decide on jj facts alone: git is not applicable, and running it there
// would only produce a bogus state-unreadable shadow over the jj rows.
func kindNeedsGit(k classify.Kind, gitBackend bool) bool {
	switch k {
	case classify.KindGitRepo, classify.KindGitWorktree:
		return true
	case classify.KindJJRepo, classify.KindJJWorkspace:
		return gitBackend
	}
	return false
}

// kindNeedsJJ: jj kinds require jj facts. A git-only repo does not.
func kindNeedsJJ(k classify.Kind) bool {
	switch k {
	case classify.KindJJRepo, classify.KindJJWorkspace,
		classify.KindJJWorkspaceOrphaned:
		return true
	}
	return false
}

func factsUnavailableWhy(in Input) string {
	if in.Git != nil && in.Git.FactsUnavailable {
		return shortWhy(in.Git.Why)
	}
	return ""
}

func branchOr(in Input, fallback string) string {
	if in.Git != nil && in.Git.Branch != "" && in.Git.Branch != "HEAD" {
		return in.Git.Branch
	}
	return fallback
}

func shortWhy(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		s = s[:77] + "..."
	}
	return s
}

func (in Input) activeHours() time.Duration {
	if in.Thresholds.ActiveHours <= 0 {
		return 48 * time.Hour
	}
	return time.Duration(in.Thresholds.ActiveHours) * time.Hour
}

// LineageGroup detects the shared-lineage shape: dirs of one origin repo
// reporting an identical huge unpushed count (the 2286-commit family).
// Detection is per-run; members keep their own reasonCode and gain a detail.
type LineageGroup struct {
	Origin  string
	Count   int
	Members []string
}

// LineageEntry is the input shape for LineageGroups.
type LineageEntry struct {
	Path     string
	Origin   string
	Unpushed int
}

// LineageGroups groups entries with the same origin and an identical
// unpushed count above threshold.
func LineageGroups(entries []LineageEntry, threshold int) []LineageGroup {
	type key struct {
		origin string
		count  int
	}
	buckets := map[key][]string{}
	for _, e := range entries {
		if e.Unpushed > threshold {
			k := key{e.Origin, e.Unpushed}
			buckets[k] = append(buckets[k], e.Path)
		}
	}
	var out []LineageGroup
	for k, members := range buckets {
		if len(members) > 1 {
			out = append(out, LineageGroup{Origin: k.origin, Count: k.count, Members: members})
		}
	}
	return out
}
