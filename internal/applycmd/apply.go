// Package applycmd implements `reap plan` and `reap apply`: the deletion
// pipeline. The spec's choreography, in order: print the plan (naming
// widened codes and counts), preflight free space (refusing below the
// floor), require TTY-confirm or --yes (never infer from EOF; 121 when
// non-interactive without --yes), take apply.lock, then per path  -
// re-verify the verdict seconds before deletion at FULL scan strength
// (same facts, same gh join, fresh walk tripwire, fetch --prune, rename
// in-use probe), require the fresh verdict to MATCH the planned one, skip
// and log anything that changed, delete children before parents, contents
// before .git/.jj, deregister before removal, write the audit trail ahead
// of every deletion, and end with the deleted/excluded/skipped summary
// and exit band.
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

	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/ghx"
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/jjx"
	"github.com/deblasis/reap/internal/lockfile"
	"github.com/deblasis/reap/internal/verdict"
	"github.com/deblasis/reap/internal/walk"
)

// Exit band (spec): 0 fully executed; 2 executed with skips; 120 usage;
// 121 not interactive; 122 config/state/lock; 123 root missing; 124
// deletion failed (path named); 125 quarantine/prune failure.
const (
	ExitOK          = 0
	ExitWithSkips   = 2
	ExitUsage       = 120
	ExitNotTTY      = 121
	ExitState       = 122
	ExitRootMissing = 123
	ExitDeleteFail  = 124
	ExitQuarantine  = 125
)

// skipWhy values: the spec's CLOSED seven-value enum (Data model). No
// other string may appear in a skip line's skipWhy field.
const (
	SkipGitBusy         = "git-busy" // index.lock at capture time
	SkipActiveTripwire  = "active-tripwire"
	SkipInUseProbe      = "in-use-probe"
	SkipVerdictChanged  = "verdict-changed"
	SkipParentLive      = "parent-of-live-children"
	SkipIgnorance       = "ignorance-unreadable"
	SkipSnapshotOvercap = "snapshot-overcap"
)

// PlanEntry is one path the plan proposes to delete.
type PlanEntry struct {
	Path         string   `json:"path"`
	Verdict      string   `json:"verdict"`
	Code         string   `json:"reasonCode"`
	SizeBytes    int64    `json:"sizeBytes"`
	Widened      bool     `json:"widened"`
	Kind         string   `json:"kind"`
	ParentRepo   string   `json:"parentRepoPath,omitempty"`
	Orphaned     bool     `json:"orphanedCarveOut,omitempty"`
	OrphanCounts string   `json:"-"`                 // knowable counts for the hardened confirm
	Flavor       string   `json:"-"`                 // verdict.Flavor (deregistered vs default orphan copy)
	Residue      string   `json:"residue,omitempty"` // nested/reflog overlap note
	PlanChildren []string `json:"-"`                 // scan-time live children; unlock-only
}

// Summary is the run's end state (apply --json body and summary source).
type Summary struct {
	RunID         string        `json:"runId"`
	Planned       []string      `json:"planned"`
	Widened       []string      `json:"widened"`
	Deleted       []string      `json:"deleted"`
	Skipped       []SkippedPath `json:"skipped"`
	ExcludedBelow []ExcludedRef `json:"excludedBelowFloor"`
	ExcludedCodes []string      `json:"excludedByCode"`
	DeletedBytes  int64         `json:"deletedBytes"`
	ExcludedBytes int64         `json:"excludedBytes"`
	SkippedBytes  int64         `json:"skippedBytes"`
	FreeGain      uint64        `json:"freeBytesReclaimed"`
}

// SkippedPath names why a planned path survived. Why carries the closed
// skipWhy enum value in machine output; Note carries refusal prose (the
// enum must stay parseable by machines).
type SkippedPath struct {
	Path string `json:"path"`
	Why  string `json:"why"`
	Note string `json:"note,omitempty"`
}

// CoerceEmptyLists makes every list field serialize as [] instead of null
// (round 15): the same command must emit ONE shape on empty and non-empty
// runs alike - a consumer cannot branch on absent-vs-empty, and the empty
// branch used to hand-roll a literal that dropped the real buckets.
func (s *Summary) CoerceEmptyLists() {
	if s.Planned == nil {
		s.Planned = []string{}
	}
	if s.Widened == nil {
		s.Widened = []string{}
	}
	if s.Deleted == nil {
		s.Deleted = []string{}
	}
	if s.Skipped == nil {
		s.Skipped = []SkippedPath{}
	}
	if s.ExcludedBelow == nil {
		s.ExcludedBelow = []ExcludedRef{}
	}
	if s.ExcludedCodes == nil {
		s.ExcludedCodes = []string{}
	}
}

// ExcludedRef is a below-floor path kept out of the plan (never a skip).
type ExcludedRef struct {
	Path string `json:"path"`
	Size int64  `json:"sizeBytes"`
}

// Deleter carries the tool runners plus the once-per-run gh fact set, so
// re-verify runs at exactly scan strength (the round-1 blocker: without
// the gh join, every git repo re-verdicted gh-unavailable and apply could
// never delete the clean-pushed class; worse, a partial fix without the
// slug join would have silently dropped the open-PR gate at deletion
// time).
type Deleter struct {
	Git     gitx.Runner
	JJ      jjx.Runner
	PRHeads *ghx.PRHeads
}

// ReverifyResult carries everything the audit intent line needs: the fresh
// verdict, the facts it came from, and the capped manifest captured while
// the dir still existed (round 2: capturing it after Delete stamped the
// unreadable-error stub on every line). HardAbort (not SkipWhy) carries
// probe-strand failures: skipWhy is the spec's closed enum and a stranded
// probe is a hard error, not a skip cause.
type ReverifyResult struct {
	SkipWhy   string
	HardAbort string
	Verdict   verdict.Verdict
	Git       *gitx.Facts
	Class     classify.Info
	Nested    []string // nested repo paths (walk evidence; discard names them)
	Manifest  []byte
	Residue   string
}

// IsTerminal reports whether BOTH stdin and stdout are interactive: a
// piped answer into a TTY session must not auto-confirm, and a redirected
// stdout with a live stdin must not falsely 121.
func IsTerminal(in *os.File, out io.Writer) bool {
	f, ok := out.(*os.File)
	if !ok || !isTerminalFd(f) {
		return false
	}
	return in != nil && isTerminalFd(in)
}

// Options carries the confirm-shaping flags plus the stderr stream for
// refusal copy (round 3: the preflight refusal printed to stdout unlike
// every other refusal).
type Options struct {
	Yes    bool
	DryRun bool
	JSON   bool
	ErrOut io.Writer
}

// Confirm prints the plan, enforces the free-space floor, and asks.
// Returns (proceed, exitCode).
func Confirm(out io.Writer, in *os.File, plan []PlanEntry, widenedCodes []string, minFree, free uint64, opts Options) (bool, int) {
	var totalBytes int64
	for _, p := range plan {
		totalBytes += p.SizeBytes
	}
	fmt.Fprintf(out, "reap will permanently delete %d directories, %.1f GB logical (not recycled)", len(plan), float64(totalBytes)/(1<<30))
	if len(widenedCodes) > 0 {
		fmt.Fprintf(out, "; %d widened via %s", len(widenedCodes), strings.Join(dedupe(widenedCodes), ","))
	}
	fmt.Fprintln(out)
	// The floor is a refusal, not a print: it exists so the audit append
	// can never wedge (spec). Refusal copy goes to stderr.
	if minFree > 0 && free < minFree {
		if opts.ErrOut != nil {
			fmt.Fprintf(opts.ErrOut, "preflight refused: %d MB free required, %d MB free\n", minFree/(1<<20), free/(1<<20))
		}
		return false, ExitState
	}
	if minFree > 0 {
		fmt.Fprintf(out, "preflight: %d MB free required, %d MB free\n", minFree/(1<<20), free/(1<<20))
	}
	if opts.DryRun {
		fmt.Fprintln(out, "dry-run: nothing will be deleted")
		return false, ExitOK
	}
	if !opts.Yes {
		if !IsTerminal(in, out) {
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

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// OrderChildrenFirst emits every plan entry in lineage order  -  children
// before parents, at any depth (a grandchild chain was silently dropped by
// the two-level version; planned-but-never-emitted is the worst shape a
// plan can have).
func OrderChildrenFirst(plan []PlanEntry) []PlanEntry {
	// Depth = number of ancestors also in the set; emit ascending depth.
	inSet := map[string]int{}
	for i, p := range plan {
		inSet[config.Canonical(p.Path)] = i
	}
	depth := make([]int, len(plan))
	for i, p := range plan {
		d := 0
		cur := p.ParentRepo
		visited := map[int]bool{i: true}
		for cur != "" {
			j, ok := inSet[config.Canonical(cur)]
			if !ok || visited[j] {
				break // self-parenting roots terminate here
			}
			visited[j] = true
			d++
			cur = plan[j].ParentRepo
		}
		depth[i] = d
	}
	// Overlapping roots (round 6): PATH NESTING counts toward depth too.
	// roots=[X, X/mass] put a parent and its inner-root children in one
	// plan with NO ParentRepo lineage between them; the parent deleting
	// first destroyed the children (live-proven by the R5 reliability
	// seat - including a user hold under the parent, 'holds beat every
	// rule' broken by ordering alone). Canonical forms are computed ONCE
	// (round 7: the O(n^2) pass re-canonicalized every path per pair).
	canon := make([]string, len(plan))
	for i, p := range plan {
		canon[i] = config.Canonical(p.Path)
	}
	for i := range plan {
		for j := range plan {
			if i == j || canon[i] == canon[j] {
				continue
			}
			if NestedUnder(canon[i], canon[j]) {
				depth[i]++ // i sits under j: j is a plan-set ancestor
			}
		}
	}
	order := make([]int, len(plan))
	for i := range order {
		order[i] = i
	}
	// DESCENDING depth: children (deeper) delete first. The test caught the
	// ascending version deleting the parent before its own child.
	for i := 0; i < len(order); i++ {
		for j := i + 1; j < len(order); j++ {
			if depth[order[j]] > depth[order[i]] {
				order[i], order[j] = order[j], order[i]
			}
		}
	}
	out := make([]PlanEntry, 0, len(plan))
	for _, i := range order {
		out = append(out, plan[i])
	}
	return out
}

// opHeadsUnchanged reports whether the repo's current op-head names are
// exactly the captured set. NO entry means no capture ever ran (the
// git-worktree family) or the capture read failed - both REFUSE (the
// R10 fail-closed fold).
func opHeadsUnchanged(captured []string, repoDir string) bool {
	if captured == nil {
		// FAIL-CLOSED (R10; the eng seat's second live-proven hole): no
		// capture exists only when this run's own deregistration never ran
		// (a git-worktree child of a colocated parent) or the capture read
		// failed - in both, a fresh op can only be GENUINE (or unknown):
		// refuse.
		return false
	}
	// Reference point: the capture taken immediately AFTER this run's own
	// deregistration (the sub-window between forget and capture is accepted
	// by design; a genuine op after the capture changes the set).
	cur := jjx.OpHeadNames(repoDir)
	if len(cur) != len(captured) {
		return false
	}
	for i := range cur {
		if cur[i] != captured[i] {
			return false
		}
	}
	return true
}

// hasDeletedChild reports whether this run deleted a path under parent.
func hasDeletedChild(deletedInRun map[string]bool, path string) bool {
	if len(deletedInRun) == 0 {
		return false
	}
	pc := config.Canonical(path)
	for d := range deletedInRun {
		if NestedUnder(config.Canonical(d), pc) {
			return true
		}
	}
	return false
}

// anyChildDeleted reports whether any of the plan's recorded children (already
// canonical, captured at plan time) went in this run.
func anyChildDeleted(planChildren []string, deletedInRun map[string]bool) bool {
	for _, ch := range planChildren {
		if deletedInRun[ch] {
			return true
		}
	}
	return false
}

// NestedUnder reports whether child sits strictly under parent (canonical
// paths; component-boundary prefix).
func NestedUnder(child, parent string) bool {
	return strings.HasPrefix(child, parent+string(os.PathSeparator))
}

// HoldUnderPath reports an ACTIVE hold naming a dir at or under path - the
// CONTAINMENT direction anyHoldUnder never checked (it walks UP from the
// candidate): a hold on an inner dir must stop its parent's deletion too
// (holds beat every rule; overlapping roots made the inner dir invisible
// to lineage ordering, live-proven by the R5 reliability seat).
func HoldUnderPath(holds map[string]bool, path string) (string, bool) {
	pn := config.Canonical(path)
	for h := range holds {
		hn := config.Canonical(h)
		if hn == pn || NestedUnder(hn, pn) {
			return h, true
		}
	}
	return "", false
}

// Reverify re-runs the deletion-time checks for one PLANNED path at full
// strength: fresh facts including the gh join and remote slugs, fresh walk
// tripwire, fetch --prune, the rename in-use probe, and  -  the round-1
// blocker fold  -  the fresh verdict must MATCH the plan: a SAFE row must
// re-verdict SAFE (clean-pushed), a widened row must carry the same
// reasonCode, and any drift (including parent-of-live-children) skips.
// deletedInRun carries the paths this run has already deleted: a widened
// parent-of-live-children row whose children all went in this run is the
// SPEC'S EXPECTED UNLOCK when it re-verdicts SAFE  -  not drift (round 2:
// the match gate alone made the both-clean family structurally undeletable).
func Reverify(path, plannedCode string, widened bool, cfg config.Config, d Deleter, protectExpanded []string, holds map[string]bool, deletedInRun map[string]bool, planChildren []string, deregOpHeads map[string][]string) ReverifyResult {
	now := time.Now()
	remoteStale := time.Duration(cfg.Thresholds.RemoteStaleHours) * time.Hour

	// Heal strays first (never overwrite: a stranded probe name with a live
	// original parks as .reap-orphaned-<ts> and is surfaced, not merged).
	HealProbingStrays(filepath.Dir(path))

	// FETCH_HEAD mtime capture: the apply-time fetch freshens it, and the
	// walk reads .git internals as activity  -  without the restore, every
	// repo that SURVIVES an apply (skip/abort) verdicts ACTIVE for 48h and
	// vanishes from subsequent plans (round 2's feedback-loop find). The
	// marker is resolved through the OWN gitdir AND the common dir (a linked
	// worktree's .git is a FILE; which of the two the fetch writes has
	// varied across git versions, so both are captured and restored).
	var fhPaths []string
	var fhMtimes []time.Time
	for _, g := range gitDirsForFetchHead(path) {
		fp := filepath.Join(g, "FETCH_HEAD")
		if fi, err := os.Stat(fp); err == nil {
			fhPaths = append(fhPaths, fp)
			fhMtimes = append(fhMtimes, fi.ModTime())
		}
	}
	restoreFetchHead := func() {
		for i, fp := range fhPaths {
			_ = os.Chtimes(fp, fhMtimes[i], fhMtimes[i])
		}
	}

	// Fresh walk: lastActivity NEVER from cache (the spec's structural rule).
	info := walk.Entry(filepath.Dir(path), path, now)
	if info.Partial {
		return ReverifyResult{SkipWhy: SkipIgnorance, Verdict: verdict.Verdict{Verdict: verdict.Manual, Code: "state-unreadable"}}
	}
	// A dir whose child THIS RUN deleted shows its own stamp bumped (the
	// directory listing changed): that is this run's doing, not user
	// activity, and the children-first ordering (lineage + path nesting,
	// round 6) made parent-after-child deletion a first-class shape. The
	// child may be a PATH child (overlapping roots) OR a LINEAGE child
	// (worktree/workspace: a path SIBLING - jj workspace forget writes
	// fresh files into the parent's .jj, the R6 eng seat's live finding).
	// When this run deleted either kind the tripwire re-reads over the
	// REMAINING children: their stamps are the user's - and this run's OWN
	// deregistration writes into .git/.jj are skipped (a genuine
	// concurrent commit still trips the run through the verdict match, not
	// the tripwire). A FAILED re-read fails toward the tripwire: an
	// unreadable activity set is never a quiet one (the R6 reliability
	// minor).
	childDeleted := hasDeletedChild(deletedInRun, path) || anyChildDeleted(planChildren, deletedInRun)
	if now.Sub(info.MaxMtime) < 2*time.Hour && childDeleted {
		if childMax, ok := walk.ChildrenMaxMtime(path, now, true); ok {
			info.MaxMtime = childMax
		}
	}
	if !info.MaxMtime.IsZero() && now.Sub(info.MaxMtime) < 2*time.Hour {
		return ReverifyResult{SkipWhy: SkipActiveTripwire, Verdict: verdict.Verdict{Verdict: verdict.Active, Code: "active"}}
	}

	classInfo := classify.Dir(path)
	in := verdict.Input{
		Path: path, Kind: classInfo.Kind, SizeBytes: info.Bytes,
		LastActivity: info.MaxMtime, NestedVCS: info.NestedVCS,
		GitBackend: classInfo.GitBackend, Thresholds: cfg.Thresholds, Now: now,
		Held:      heldUnder(holds, path),
		Protected: protected(path, protectExpanded),
		PRHeads:   d.PRHeads,
	}
	if classInfo.GitBackend || (classInfo.Kind == classify.KindGitWorktreeOrphaned && classInfo.ParentRepo != "") {
		// Apply-time strengthening: prune stale remote-tracking refs before
		// computing unpushed (offline/timeout -> remote-stale MANUAL, never
		// trust of stale refs). A repo with NO remotes skips the fetch
		// entirely: `git fetch --prune` exits nonzero there, and reading
		// that as unreadable made every no-remote repo state-unreadable at
		// deletion time  -  the discard resolver could never fire on exactly
		// the repos it exists for. Nothing to prune, no tracking refs to
		// stale; the facts below stand on their own. Budget check first:
		// budget<=0 means fetch disabled, which is NOT an error.
		// FETCH_HEAD's mtime is restored around the fetch (round 2's loop).
		remotes := d.Git.Remotes(path)
		if len(remotes) > 0 {
			if err := d.Git.FetchPrune(path); err != nil && d.Git.FetchBudget > 0 {
				restoreFetchHead()
				f := gitx.Facts{StateUnreadable: true, Why: fmt.Sprintf("fetch --prune: %v", err)}
				in.Git = &f
				return ReverifyResult{SkipWhy: SkipIgnorance, Verdict: verdict.Decide(in), Class: classInfo}
			}
		}
		f := d.Git.Facts(path, now, remoteStale)
		in.Git = &f
		for _, url := range remotes {
			if slug := ghx.SlugFromURL(url); slug != "" {
				in.RemoteSlugs = append(in.RemoteSlugs, slug)
			}
		}
	}
	restoreFetchHead()
	flavorDeregistered := false
	if classInfo.Kind == classify.KindJJRepo || classInfo.Kind == classify.KindJJWorkspace {
		f := d.JJ.Facts(path, now, remoteStale)
		// WORKSPACE-shaped only (the parent resolved alive at classify).
		if f.Deregistered && classInfo.Kind == classify.KindJJWorkspace {
			// The forget-then-rm shape at RE-VERIFY (round 10): the fresh
			// classification says jj-workspace (parent alive), but the dir
			// is out of the parent's registry. Re-verdict as the orphaned
			// row so a planned orphaned-workspace widening MATCHES and the
			// carve-out is genuinely executable.
			classInfo = classify.Info{Kind: classify.KindJJWorkspaceOrphaned}
			in.Kind = classInfo.Kind
			in.GitBackend = false
			in.JJ = nil
			flavorDeregistered = true
		} else {
			in.JJ = &f
		}
	}
	v := verdict.Decide(in)
	if flavorDeregistered {
		v.Flavor = verdict.FlavorDeregistered
		if v.Code == "orphaned-workspace" {
			v.Reason = "deregistered workspace (parent alive, this dir is out of its registry)"
			v.Hint = "deregistered workspace (parent alive, this dir is out of its registry); reap apply --override-manual asks a TTY-only hardened confirm"
		}
	}

	// Ignorance-class fresh verdicts (gh died mid-run etc.) report as
	// ignorance, not verdict-changed (round 2: the histogram misled).
	if isIgnoranceCodeLocal(v.Code) {
		return ReverifyResult{SkipWhy: SkipIgnorance, Verdict: v, Git: in.Git, Class: classInfo, Nested: info.NestedVCS}
	}
	// MATCH gate: the fresh verdict must equal the planned one.
	if v.BlockedClassFact != "" && !v.OrphanedCarveOut {
		return ReverifyResult{SkipWhy: SkipVerdictChanged, Verdict: v, Git: in.Git, Class: classInfo, Nested: info.NestedVCS}
	}
	if v.Code == "parent-of-live-children" {
		return ReverifyResult{SkipWhy: SkipParentLive, Verdict: v, Git: in.Git, Class: classInfo, Nested: info.NestedVCS}
	}
	switch {
	case widened:
		if v.Verdict != verdict.Manual || v.Code != plannedCode {
			// The in-run unlock: a widened parent-of-live-children row that
			// re-verdicts SAFE and whose PLAN-TIME children all went in this
			// run. The fresh enumeration is empty post-deregistration, so the
			// comparison is against what the plan saw (round 3's proof that
			// the fresh-set variant was structurally false).
			//
			// The jj-active arm (round 7; the R6 eng seat's live-dead jj
			// unlock): this run's own forget/deregistration ops are fresh in
			// the SHARED op store, so the parent re-verdicts jj-active even
			// though the walk is quiet (the tripwire re-read above already
			// passed with the deregistration exemption). Accepting it is
			// gated on the same all-children-deleted condition.
			if plannedCode == "parent-of-live-children" &&
				allPlanChildrenDeleted(planChildren, deletedInRun) &&
				(v.Verdict == verdict.Safe || (v.Verdict == verdict.Active && v.Code == "jj-active" &&
					// Op identity (round 9; the R7 reliability seat live-proved a
					// GENUINE interposed 'jj git fetch' rode the arm): the arm is
					// accepted only when the op-head set is EXACTLY the one this
					// run's own deregistration left behind. A new op-head name =
					// a genuine later op - refuse.
					opHeadsUnchanged(deregOpHeads[config.Canonical(path)], path))) {
				break
			}
			return ReverifyResult{SkipWhy: SkipVerdictChanged, Verdict: v, Git: in.Git, Class: classInfo}
		}
	default: // SAFE-planned
		if v.Verdict != verdict.Safe {
			return ReverifyResult{SkipWhy: SkipVerdictChanged, Verdict: v, Git: in.Git, Class: classInfo}
		}
	}

	// Capture the manifest NOW: the dir exists (post-walk, pre-probe), and
	// Delete will remove it (round 2: post-Delete capture stamped the
	// unreadable stub on every line).
	manifest := []byte(nil)
	residue := ""
	if plannedCode != "clean-pushed" {
		manifest = walk.CappedManifest(path)
	}
	if len(info.NestedVCS) > 0 {
		residue = fmt.Sprintf("nested repos: %d", len(info.NestedVCS))
	} else if in.Git != nil && in.Git.ReflogOnly > 0 {
		residue = fmt.Sprintf("reflog-only: %d", in.Git.ReflogOnly)
	}

	// Rename in-use probe: deterministic sibling, \\?\ long-safe paths,
	// restore retried; a restore failure is a hard error the caller turns
	// into an abort naming the new path.
	if err := renameProbe(path); err != nil {
		if errors.Is(err, errProbeInUse) {
			return ReverifyResult{SkipWhy: SkipInUseProbe, Verdict: v, Git: in.Git, Class: classInfo, Nested: info.NestedVCS, Manifest: manifest, Residue: residue}
		}
		return ReverifyResult{HardAbort: fmt.Sprintf("probe stranded for %s: %v", path, err), Verdict: v, Git: in.Git, Class: classInfo, Nested: info.NestedVCS, Manifest: manifest, Residue: residue}
	}
	return ReverifyResult{Verdict: v, Git: in.Git, Class: classInfo, Nested: info.NestedVCS, Manifest: manifest, Residue: residue}
}

// gitDirsForFetchHead lists the per-worktree gitdir and the common git dir
// for path (root repos: the same dir twice, deduped by the caller's stat
// loop; linked worktrees: both the private gitdir and the parent's .git).
func gitDirsForFetchHead(path string) []string {
	var out []string
	if g, ok := gitDirForPath(path); ok {
		out = append(out, g)
	}
	if c, ok := gitCommonDirFor(path); ok {
		out = append(out, c)
	}
	return out
}

// gitDirForPath resolves the candidate's own git dir (.git dir or the
// linked .git file's gitdir pointer).
func gitDirForPath(path string) (string, bool) {
	gitPath := filepath.Join(path, ".git")
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
		s = filepath.Join(path, s)
	}
	return s, true
}

// gitCommonDirFor resolves the common git dir (the parent's .git for
// linked worktrees; identity for root repos).
func gitCommonDirFor(path string) (string, bool) {
	s, ok := gitDirForPath(path)
	if !ok {
		return "", false
	}
	if i := strings.Index(filepath.ToSlash(s), "/worktrees/"); i >= 0 {
		return filepath.FromSlash(filepath.ToSlash(s)[:i]), true
	}
	return s, true
}

func isIgnoranceCodeLocal(code string) bool {
	switch code {
	case "facts-unavailable", "state-unreadable", "remote-stale", "jj-remote-stale", "gh-unavailable", "unknown-kind":
		return true
	}
	return false
}

// allPlanChildrenDeleted reports whether every PLAN-TIME live child went in
// this run's deletion set (the in-set unlock).
func allPlanChildrenDeleted(planChildren []string, deletedInRun map[string]bool) bool {
	if len(planChildren) == 0 {
		return false
	}
	// planChildren arrive ALREADY canonical (captured at plan time while
	// the children existed - round 7: re-canonicalizing here would fail to
	// expand 8.3 components of children this run has since deleted).
	for _, ch := range planChildren {
		if !deletedInRun[ch] {
			return false
		}
	}
	return true
}

var errProbeInUse = errors.New("dir is in use (rename refused)")

// InUseProbe runs the rename in-use probe standalone: discard needs it even
// though Reverify's BLOCKED early return (the match gate) never reaches its
// own probe. A dir a live process holds open must not be
// quarantined-then-deleted any more than silently deleted.
func InUseProbe(path string) (inUse bool, stranded error) {
	err := renameProbe(path)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, errProbeInUse) {
		return true, nil
	}
	return false, err
}

func longPath(p string) string {
	if len(p) > 240 || strings.HasPrefix(p, `\\?\`) {
		if !strings.HasPrefix(p, `\\?\`) {
			return `\\?\` + p
		}
	}
	return p
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

// HealProbingStrays heals .reap-probing leftovers in dir: original absent ->
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

// Delete removes one path: deregister first (worktree remove FROM THE
// PARENT  -  git -C on the doomed worktree makes it git's own cwd, so the
// remove reliably fails after deregistering, which is how the round-1
// probe caught it  -  jj workspace forget must succeed), then rm with
// contents-before-VCS ordering. The audit lines are written by the CALLER
// (intent before, result after): the round-1 Delete wrote its own
// mislabeled line on one branch and ignored its error.
func Delete(path string, classInfo classify.Info, d Deleter) (mode string, err error) {
	mode = "rm"
	if classInfo.Kind == classify.KindGitWorktree && classInfo.ParentRepo != "" {
		if err := d.Git.WorktreeRemoveFrom(path, classInfo.ParentRepo); err == nil {
			return "worktree-remove", nil
		}
		// Fall through to rm; prune the stale registration after.
		if err := removeContentsBeforeVCS(path); err != nil {
			return mode, err
		}
		_ = d.Git.WorktreePrune(classInfo.ParentRepo)
		return "worktree-remove+rm", nil
	}
	// WORKSPACES only (round 9): a jj ROOT repo has no workspace to forget
	//  -  jj 0.44's forget of a nonexistent name is an exit-0 "Nothing
	// changed" warning, so running it anyway labeled root deletions
	// mode=jj-forget+rm, asserting a deregistration that never happened.
	if classInfo.Kind == classify.KindJJWorkspace && classInfo.ParentRepo != "" {
		if err := d.JJ.WorkspaceForget(classInfo.ParentRepo, workspaceName(classInfo.ParentRepo, path, d.JJ)); err != nil {
			// Spec: forget must succeed before rm; failure routes MANUAL.
			return mode, fmt.Errorf("%w: jj workspace forget: %v", errDeregister, err)
		}
		mode = "jj-forget+rm"
	}
	if err := removeContentsBeforeVCS(path); err != nil {
		return mode, err
	}
	return mode, nil
}

var errDeregister = errors.New("deregistration failed")

// workspaceName resolves the jj workspace name from the parent's registry
// (the dir base need not equal the registered name  -  the round-1 find).
func workspaceName(parent, path string, jr jjx.Runner) string {
	f := jr.WorkspaceListNames(parent)
	for name, p := range f {
		if config.Canonical(p) == config.Canonical(path) {
			return name
		}
	}
	return filepath.Base(path)
}

// removeContentsBeforeVCS deletes everything except the VCS metadata first,
// then the metadata: a partial failure preserves history and reflog  -  the
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
// holder (PID + runId written into the lock body  -  the spec asks for
// both). The runId is MINTED BY THE CALLER before locking so the body
// carries the real run, not "unknown" (the round-2 finding).
func Lock(stateDir, runID string) (*lockfile.File, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, "apply.lock")
	l, err := lockfile.Open(path)
	if err != nil {
		return nil, err
	}
	ok, err := l.TryLock()
	if err != nil {
		return nil, err
	}
	if !ok {
		l.Close()
		holder := readLockHolder(path)
		return nil, fmt.Errorf("another reap run holds apply.lock (holder: %s); fail-fast, retry when it exits", holder)
	}
	_ = os.WriteFile(path, []byte(fmt.Sprintf("pid=%d runId=%s", os.Getpid(), runID)), 0o644)
	return l, nil
}

func readLockHolder(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return "unknown"
	}
	return strings.TrimSpace(string(raw))
}

// ReadHoldsSnapshotStrict reads holds.json distinguishing missing (ok, empty)
// from CORRUPT (error): a writer must refuse corrupt rather than overwrite
// existing holds (round 2: cmdHold silently wiped a corrupt file).
func ReadHoldsSnapshotStrict(stateDir string) (map[string]time.Time, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "holds.json"))
	if os.IsNotExist(err) {
		return map[string]time.Time{}, nil
	}
	if err != nil {
		return nil, err
	}
	var hf map[string]struct {
		Expires time.Time `json:"expires"`
	}
	if uerr := json.Unmarshal(raw, &hf); uerr != nil {
		return nil, fmt.Errorf("holds.json is corrupt (refusing to overwrite holds): %w", uerr)
	}
	out := map[string]time.Time{}
	for p, h := range hf {
		out[config.Canonical(p)] = h.Expires
	}
	return out, nil
}

// ReadHoldsSnapshot is the shared lenient read for display commands.
func ReadHoldsSnapshot(stateDir string) map[string]time.Time {
	out, err := ReadHoldsSnapshotStrict(stateDir)
	if err != nil {
		return nil
	}
	return out
}

// WriteHolds is the single writer of holds.json, in the exact shape every
// reader expects ({canonicalPath: {"expires": RFC3339}})  -  the round-1
// blocker was a writer/reader shape mismatch that bricked the tool.
func WriteHolds(stateDir string, hf map[string]time.Time) error {
	out := map[string]struct {
		Expires time.Time `json:"expires"`
	}{}
	for p, exp := range hf {
		out[config.Canonical(p)] = struct {
			Expires time.Time `json:"expires"`
		}{Expires: exp}
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	return config.AtomicWrite(filepath.Join(stateDir, "holds.json"), raw, 0o644)
}

func heldUnder(holds map[string]bool, path string) bool {
	if len(holds) == 0 {
		return false
	}
	pc := config.Canonical(path)
	parts := strings.Split(pc, string(os.PathSeparator))
	for i := len(parts); i >= 1; i-- {
		if holds[strings.Join(parts[:i], string(os.PathSeparator))] {
			return true
		}
	}
	return false
}

// PathHeld reports whether path (or any ancestor) is held; exported for
// discard's wave-0 rails (holds beat every rule and every flag).
func PathHeld(holds map[string]bool, path string) bool { return heldUnder(holds, path) }

func protected(path string, globs []string) bool {
	ok, _ := config.MatchProtect(path, globs)
	return ok
}
