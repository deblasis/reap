package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/applycmd"
	"github.com/deblasis/reap/internal/auditlog"
	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/ghx"
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/jjx"
	"github.com/deblasis/reap/internal/report"
	"github.com/deblasis/reap/internal/verdict"
	"github.com/deblasis/reap/internal/walk"
)

// scanCore is the shared scan/plan/apply pipeline: walk, facts, verdicts.
// The spec's invariant — plan/apply always run full-strength over the set,
// same flags as scan — falls out of sharing one implementation.
type scanCore struct {
	cfg             config.Config
	roots           []string
	noGH, noJJ      bool
	prHeads         *ghx.PRHeads
	useGit, useJJ   bool
	protectExpanded []string
	holds           map[string]bool
	// expiredHolds: canonical path -> expiry, for pins that lapsed within
	// the last 7 days (the spec's expiry-at-consequence marking).
	expiredHolds                               map[string]time.Time
	remoteStale                                time.Duration
	gitBudget, jjBudget, ghBudget, fetchBudget time.Duration
}

func newScanCore(args []string, stderr io.Writer, rootsFlag []string, noGH, noJJ bool) (*scanCore, int) {
	stateDir, err := config.StateDir()
	if err != nil {
		fmt.Fprintf(stderr, "reap: %v\n", err)
		return nil, ExitState
	}
	cfg, err := config.Load(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap: %v\n", err)
		return nil, ExitState
	}
	core := &scanCore{cfg: cfg, noGH: noGH, noJJ: noJJ}
	core.gitBudget, core.jjBudget, core.ghBudget, core.fetchBudget, err = cfg.Thresholds.Budgets()
	if err != nil {
		fmt.Fprintf(stderr, "reap: %v\n", err)
		return nil, ExitState
	}
	core.roots, err = narrowRoots(config.ExpandRoots(cfg.Roots), rootsFlag)
	if err != nil {
		fmt.Fprintf(stderr, "reap: %v\n", err)
		return nil, ExitUsage
	}
	if !core.noGH && cfg.GH {
		h := ghx.Client{Budget: core.ghBudget}.OpenPRHeads()
		core.prHeads = &h
	}
	core.useJJ = !core.noJJ && cfg.JJ && jjx.Available()
	core.useGit = gitx.Available()
	core.protectExpanded = config.ExpandRoots(cfg.Protect)
	if _, err := config.MatchProtect(".", core.protectExpanded); err != nil {
		fmt.Fprintf(stderr, "reap: %v\n", err)
		return nil, ExitState
	}
	holds, expired, err := loadHoldsWithExpired(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap: %v\n", err)
		return nil, ExitState
	}
	core.holds = holds
	core.expiredHolds = expired
	core.remoteStale = time.Duration(cfg.Thresholds.RemoteStaleHours) * time.Hour
	return core, ExitOK
}

// ExpiredHoldDetail renders the expiry-at-consequence line for a path
// ("" when the path has no recently-lapsed pin): plan's distinct section.
func (c *scanCore) ExpiredHoldDetail(path string) string {
	cp := config.Canonical(path)
	exp, ok := c.expiredHolds[cp]
	if !ok {
		return ""
	}
	return fmt.Sprintf("hold expired %s (%dd ago)", exp.Format("2006-01-02"), int(time.Since(exp).Hours()/24))
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

// candidate is one walked+verdicted dir, carrying what plan/apply need.
type candidate struct {
	entry report.Entry
	vd    verdict.Verdict
	cls   classify.Info
	// planChildren are the scan-time live children, captured for the
	// parent-of-live-children in-run unlock: after worktree-remove prunes
	// the registration, the FRESH enumeration is empty, so the unlock must
	// compare against what the plan saw (round 3's end-to-end proof).
	planChildren []string
	// expiredHold: the expiry-at-consequence detail when a pin on this dir
	// lapsed within 7 days ("" otherwise).
	expiredHold string
}

// run walks the roots and verdicts every candidate.
func (c *scanCore) run(now time.Time) ([]candidate, []string) {
	infos := walk.Roots(c.roots, now, 8)
	var unreadableRoots []string
	var out []candidate
	for _, info := range infos {
		if info.Root == info.Path {
			unreadableRoots = append(unreadableRoots, info.Path)
			continue
		}
		if info.IsReparse {
			continue // KEEP rails never enter plans
		}
		e, v, cls, pc := c.build(info, now)
		out = append(out, candidate{entry: e, vd: v, cls: cls, planChildren: pc, expiredHold: c.ExpiredHoldDetail(info.Path)})
	}
	return out, unreadableRoots
}

func (c *scanCore) build(info walk.DirInfo, now time.Time) (report.Entry, verdict.Verdict, classify.Info, []string) {
	e := report.Entry{
		Path:         info.Path,
		Zone:         info.Root,
		SizeBytes:    info.Bytes,
		SizePartial:  info.Partial,
		LastActivity: &info.MaxMtime,
		AgeDays:      int(now.Sub(info.MaxMtime).Hours() / 24),
		ClampedFiles: info.Clamped,
	}
	cls := classify.Dir(info.Path)
	e.Kind = string(cls.Kind)
	gr := gitx.Runner{GitBudget: c.gitBudget, FetchBudget: c.fetchBudget}
	jr := jjx.Runner{Budget: c.jjBudget}
	in := verdict.Input{
		Path: info.Path, Kind: cls.Kind, SizeBytes: info.Bytes,
		SizePartial: info.Partial, LastActivity: info.MaxMtime,
		NestedVCS: info.NestedVCS, GitBackend: cls.GitBackend,
		Thresholds: c.cfg.Thresholds, Now: now,
	}
	gitReachable := cls.GitBackend || (cls.Kind == classify.KindGitWorktreeOrphaned && cls.ParentRepo != "")
	if c.useGit && gitReachable {
		f := gr.Facts(info.Path, now, c.remoteStale)
		in.Git = &f
		e.Branch, e.Dirty, e.Untracked = f.Branch, f.Dirty, f.Untracked
		e.Ignored, e.Stashes, e.Unpushed = f.Ignored, f.Stashes, f.Unpushed
		e.UnpushedReflogOnly = f.ReflogOnly
		if f.FactsUnavailable || f.StateUnreadable {
			e.DowngradedBy = strPtr("git")
		}
		for name, url := range gr.Remotes(info.Path) {
			if slug := ghx.SlugFromURL(url); slug != "" {
				in.RemoteSlugs = append(in.RemoteSlugs, slug)
				if name == "origin" {
					e.Origin = slug
				}
			}
		}
	} else if gitReachable {
		e.DowngradedBy = strPtr("git")
	}
	jjReachable := cls.Kind == classify.KindJJRepo || cls.Kind == classify.KindJJWorkspace
	if c.useJJ && jjReachable {
		f := jr.Facts(info.Path, now, c.remoteStale)
		in.JJ = &f
		if f.Unavailable {
			e.DowngradedBy = strPtr("jj")
		}
	} else if jjReachable {
		e.DowngradedBy = strPtr("jj")
	}
	in.PRHeads = c.prHeads
	if c.prHeads != nil && c.prHeads.Unavailable {
		e.DowngradedBy = strPtr("gh")
	}
	in.Held = anyHoldUnder(c.holds, info.Path)
	in.Protected, _ = config.MatchProtect(info.Path, c.protectExpanded)
	v := verdict.Decide(in)
	e.Verdict, e.ReasonCode, e.Reason, e.Hint = v.Verdict, v.Code, v.Reason, v.Hint
	e.Held = in.Held
	e.BlockedClassFact = v.BlockedClassFact
	e.OrphanedCarveOut = v.OrphanedCarveOut
	e.OpenPR = v.OpenPRSlug != ""
	if v.OrphanedCarveOut && v.BlockedClassFact != "" {
		e.Reason = e.Reason + fmt.Sprintf(" (also: %s)", v.BlockedClassFact)
	}
	var planChildren []string
	if in.Git != nil {
		planChildren = append(planChildren, in.Git.Children...)
	}
	if in.JJ != nil {
		planChildren = append(planChildren, in.JJ.Children...)
	}
	return e, v, cls, planChildren
}

// resolvePlan applies SAFE-default + include/exclude/override selection,
// the --min-gb planning floor, and closed-enum validation. Orphaned
// carve-out rows are REFUSED on --override-manual/--include: their only
// sanctioned path is a TTY-only hardened confirm (spec, M3); the round-1
// probe deleted only-copy work under plain --yes.
func resolvePlan(cands []candidate, include, exclude, overrideManual []string, minGB float64) (plan []applycmd.PlanEntry, below []applycmd.ExcludedRef, excludedByCode []string, err error) {
	if e := validateCodes(include, exclude); e != nil {
		return nil, nil, nil, e
	}
	inc := map[string]bool{}
	for _, c := range include {
		inc[c] = true
	}
	exc := map[string]bool{}
	for _, c := range exclude {
		exc[c] = true
	}
	ovr := map[string]bool{}
	for _, p := range overrideManual {
		ovr[config.Canonical(p)] = true
	}
	for _, c := range cands {
		take, widened := false, false
		switch {
		case c.vd.Verdict == verdict.Safe:
			take = true
		case c.vd.OrphanedCarveOut && (inc[c.vd.Code] || ovr[config.Canonical(c.entry.Path)]):
			counts := "counts unknowable, parent gone"
			if c.vd.BlockedClassFact != "" {
				counts = c.vd.BlockedClassFact
			}
			return nil, nil, nil, &carveOutRefusal{path: c.entry.Path, counts: counts}
		case inc[c.vd.Code] && c.vd.Verdict == verdict.Manual && c.vd.BlockedClassFact == "":
			take, widened = true, true
		case ovr[config.Canonical(c.entry.Path)] && c.vd.Verdict == verdict.Manual && c.vd.BlockedClassFact == "":
			take = true
		}
		if !take {
			continue
		}
		if exc[c.vd.Code] {
			excludedByCode = append(excludedByCode, c.entry.Path)
			continue
		}
		if minGB > 0 && float64(c.entry.SizeBytes)/(1<<30) < minGB {
			below = append(below, applycmd.ExcludedRef{Path: c.entry.Path, Size: c.entry.SizeBytes})
			continue
		}
		pe := applycmd.PlanEntry{
			Path: c.entry.Path, Verdict: c.vd.Verdict, Code: c.vd.Code,
			SizeBytes: c.entry.SizeBytes, Widened: widened, Kind: string(c.cls.Kind),
			ParentRepo: c.cls.ParentRepo, Orphaned: c.vd.OrphanedCarveOut,
		}
		if c.vd.Code == "parent-of-live-children" {
			for _, ch := range c.planChildren {
				pe.PlanChildren = append(pe.PlanChildren, ch)
			}
		}
		plan = append(plan, pe)
	}
	for _, code := range include {
		used := false
		for _, p := range plan {
			if p.Code == code {
				used = true
			}
		}
		if !used {
			for _, c := range cands {
				if c.vd.Code == code && (c.vd.BlockedClassFact != "" || c.vd.Verdict == verdict.Blocked ||
					c.vd.Verdict == verdict.Active || c.vd.Verdict == verdict.Keep) {
					return nil, nil, nil, fmt.Errorf("--include %s matched only non-deletable rows (e.g. %s: %s)", code, c.entry.Path, c.vd.Verdict)
				}
			}
		}
	}
	return plan, below, excludedByCode, nil
}

// carveOutRefusal is the orphaned carve-out refusal: 120 from plan, 121
// from non-TTY apply --yes, counts always in the message (spec interim).
type carveOutRefusal struct{ path, counts string }

func (e *carveOutRefusal) Error() string {
	return fmt.Sprintf("%s is an orphaned carve-out row (%s): deletable only via the TTY-only hardened confirm (ships with M3); refusing under --include/--override-manual", e.path, e.counts)
}

// validateCodes checks include/exclude against the closed reasonCode enum.
func validateCodes(include, exclude []string) error {
	all := append(append([]string{}, include...), exclude...)
	for _, c := range all {
		if !verdict.IsReasonCode(c) {
			return fmt.Errorf("--include/--exclude %q is not a reasonCode (closed enum; scan --json lists codes)", c)
		}
	}
	return nil
}

// renderPlanText is THE plan renderer: cmdPlan and cmdApply --dry-run both
// call it, byte-identically (the spec's tie; round 1 proved two renderers
// drift within one review cycle).
func renderPlanText(w io.Writer, plan []applycmd.PlanEntry, below []applycmd.ExcludedRef, widened []string, expired []expiredHoldRef) {
	var total int64
	for _, p := range plan {
		total += p.SizeBytes
	}
	fmt.Fprintf(w, "reap will permanently delete %d directories, %.1f GB logical (not recycled)", len(plan), float64(total)/(1<<30))
	if len(widened) > 0 {
		fmt.Fprintf(w, "; %d widened via %s", len(widened), strings.Join(dedupeStrings(widened), ","))
	}
	fmt.Fprintln(w)
	for _, p := range plan {
		fmt.Fprintf(w, "%8.1f GB  %s  [%s]\n", float64(p.SizeBytes)/(1<<30), p.Path, p.Code)
	}
	if len(below) > 0 {
		fmt.Fprintf(w, "%d below --min-gb floor (excluded, not listed)\n", len(below))
	}
	for _, ex := range expired {
		fmt.Fprintf(w, "expired hold: %s  %s\n", ex.path, ex.detail)
	}
	fmt.Fprintln(w, "dry-run: nothing will be deleted")
}

// expiredHoldRef is one row of plan's distinct expired-hold section.
type expiredHoldRef struct{ path, detail string }

// collectExpired gathers the expiry-at-consequence rows for plan's section.
func collectExpired(cands []candidate) []expiredHoldRef {
	var out []expiredHoldRef
	for _, c := range cands {
		if c.expiredHold != "" {
			out = append(out, expiredHoldRef{path: c.entry.Path, detail: c.expiredHold})
		}
	}
	return out
}

func dedupeStrings(in []string) []string {
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

func planWidenedCodes(plan []applycmd.PlanEntry) []string {
	var out []string
	for _, p := range plan {
		if p.Widened {
			out = append(out, p.Code)
		}
	}
	return out
}

func renderPlanJSON(w io.Writer, now time.Time, plan []applycmd.PlanEntry, below []applycmd.ExcludedRef) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		Generated string                 `json:"generated"`
		Planned   []applycmd.PlanEntry   `json:"planned"`
		BelowMin  []applycmd.ExcludedRef `json:"excludedBelowFloor"`
	}{now.Format(time.RFC3339), plan, below}); err != nil {
		return ExitState
	}
	return ExitOK
}

// cmdPlan implements `reap plan`.
func cmdPlan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootsFlag := multiFlag{}
	fs.Var(&rootsFlag, "roots", "narrow to these configured roots")
	minGB := fs.Float64("min-gb", 0, "planning floor (GB)")
	noGH := fs.Bool("no-gh", false, "skip the open-PR fact (weakens verdicts)")
	noJJ := fs.Bool("no-jj", false, "skip jj facts (weakens verdicts)")
	include := multiFlag{}
	fs.Var(&include, "include", "widen into a judgment-class MANUAL code (repeatable)")
	exclude := multiFlag{}
	fs.Var(&exclude, "exclude", "narrow out a reason code (repeatable)")
	asJSON := fs.Bool("json", false, "emit the machine schema")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	core, code := newScanCore(args, stderr, rootsFlag, *noGH, *noJJ)
	if core == nil {
		return code
	}
	now := time.Now()
	cands, _ := core.run(now)
	plan, below, _, err := resolvePlan(cands, include, exclude, nil, *minGB)
	if err != nil {
		fmt.Fprintf(stderr, "reap plan: %v\n", err)
		return ExitUsage
	}
	if *asJSON {
		return renderPlanJSON(stdout, now, plan, below)
	}
	renderPlanText(stdout, plan, below, planWidenedCodes(plan), collectExpired(cands))
	return ExitOK
}

// cmdApply implements `reap apply`.
func cmdApply(args []string, stdout, stderr io.Writer, stdin *os.File) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootsFlag := multiFlag{}
	fs.Var(&rootsFlag, "roots", "narrow to these configured roots")
	minGB := fs.Float64("min-gb", 0, "planning floor (GB)")
	noGH := fs.Bool("no-gh", false, "skip the open-PR fact (weakens verdicts)")
	noJJ := fs.Bool("no-jj", false, "skip jj facts (weakens verdicts)")
	include := multiFlag{}
	fs.Var(&include, "include", "widen into a judgment-class MANUAL code (repeatable)")
	exclude := multiFlag{}
	fs.Var(&exclude, "exclude", "narrow out a reason code (repeatable)")
	overrideManual := multiFlag{}
	fs.Var(&overrideManual, "override-manual", "relax the MANUAL gate for exactly this path (repeatable)")
	asJSON := fs.Bool("json", false, "emit the machine schema")
	yes := fs.Bool("yes", false, "confirm non-interactively")
	dryRun := fs.Bool("dry-run", false, "print the plan and exit (byte-identical to reap plan)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	stateDir, err := config.StateDir()
	if err != nil {
		fmt.Fprintf(stderr, "reap apply: %v\n", err)
		return ExitState
	}
	core, code := newScanCore(args, stderr, rootsFlag, *noGH, *noJJ)
	if core == nil {
		return code
	}
	now := time.Now()
	cands, unreadableRoots := core.run(now)
	// Root-missing is 123 in the apply family (read-only commands never
	// emit family codes).
	if len(unreadableRoots) > 0 {
		for _, u := range unreadableRoots {
			fmt.Fprintf(stderr, "reap apply: unreadable/missing root: %s\n", u)
		}
		return applycmd.ExitRootMissing
	}
	plan, below, byCode, err := resolvePlan(cands, include, exclude, overrideManual, *minGB)
	if err != nil {
		var co *carveOutRefusal
		if errors.As(err, &co) && *yes && !applycmd.IsTerminal(stdin, stdout) {
			fmt.Fprintf(stderr, "reap apply: %v\n", err)
			return applycmd.ExitNotTTY
		}
		fmt.Fprintf(stderr, "reap apply: %v\n", err)
		return ExitUsage
	}

	// The dry-run tie: delegate to the exact plan renderer — byte-identical
	// in text AND json (round-1 blocker).
	if *dryRun {
		if *asJSON {
			return renderPlanJSON(stdout, now, plan, below)
		}
		renderPlanText(stdout, plan, below, planWidenedCodes(plan), collectExpired(cands))
		return ExitOK
	}

	// Preflight floor: a refusal, not a print.
	minFree := uint64(core.cfg.Thresholds.MinFreeMB) << 20
	free := auditlog.FreeBytes(stateDir)
	widened := planWidenedCodes(plan)
	proceed, ccode := applycmd.Confirm(stdout, stdin, plan, widened, minFree, free, applycmd.Options{Yes: *yes, ErrOut: stderr})
	if !proceed {
		return ccode
	}

	// Exclusive lock for the whole run.
	lock, err := applycmd.Lock(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap apply: %v\n", err)
		return ExitState
	}
	defer lock.Close()

	runID := auditlog.NewRunID()
	log, err := auditlog.Open(stateDir, runID)
	if err != nil {
		fmt.Fprintf(stderr, "reap apply: %v\n", err)
		return ExitState
	}
	freeBefore := auditlog.FreeBytes(stateDir)

	ordered := applycmd.OrderChildrenFirst(plan)
	summary := applycmd.Summary{RunID: runID, Planned: pathsOf(plan),
		Widened: widenedPaths(plan), ExcludedBelow: below, ExcludedCodes: byCode}
	// The envelope is written on EVERY exit path from here (deferred):
	// aborts mid-run leave an auditable session record.
	defer func() {
		_ = log.Append(auditlog.Line{Event: "envelope", Planned: len(plan),
			Deleted: len(summary.Deleted), Skipped: len(summary.Skipped),
			FreeBefore: freeBefore, FreeAfter: auditlog.FreeBytes(stateDir), Quarantine: nil})
	}()
	appendOrAbort := func(line auditlog.Line) int {
		if err := log.Append(line); err != nil {
			fmt.Fprintf(stderr, "reap apply: HARD ABORT: %v\n", err)
			return ExitState
		}
		return -1
	}

	d := applycmd.Deleter{
		Git:     gitx.Runner{GitBudget: core.gitBudget, FetchBudget: core.fetchBudget},
		JJ:      jjx.Runner{Budget: core.jjBudget},
		PRHeads: core.prHeads,
	}
	deletedInRun := map[string]bool{}
	for _, p := range ordered {
		intent := auditlog.Line{
			Event: "intent", Path: p.Path, Kind: p.Kind, SizeBytes: p.SizeBytes,
			Verdict: p.Verdict, ReasonCode: p.Code, Quarantine: nil,
		}
		if rc := appendOrAbort(intent); rc >= 0 {
			return rc
		}
		rv := applycmd.Reverify(p.Path, p.Code, p.Widened, core.cfg, d, core.protectExpanded, core.holds, deletedInRun, p.PlanChildren)
		if rv.HardAbort != "" {
			fmt.Fprintf(stderr, "reap apply: HARD ABORT: %s\n", rv.HardAbort)
			return ExitState
		}
		if rv.SkipWhy != "" {
			summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{Path: p.Path, Why: rv.SkipWhy})
			summary.SkippedBytes += p.SizeBytes
			ok := false
			if rc := appendOrAbort(auditlog.Line{Event: "skip", Path: p.Path, SkipWhy: rv.SkipWhy,
				Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, OK: &ok, Quarantine: nil}); rc >= 0 {
				return rc
			}
			continue
		}
		mode, err := applycmd.Delete(p.Path, rv.Class, d)
		if err != nil {
			// Deregistration failure is a deletion failure (spec's exit
			// band: 124, path named) — not a skip: skipWhy is the spec's
			// closed enum and the dir is still standing either way.
			ok := false
			_ = log.Append(auditlog.Line{Event: "result", Path: p.Path, Mode: mode, OK: &ok, Quarantine: nil})
			fmt.Fprintf(stderr, "reap apply: deletion failed: %s: %v\n", p.Path, err)
			return applycmd.ExitDeleteFail
		}
		// The in-run deletion set feeds the both-clean unlock (round-3: the
		// map existed but was never written — dead wiring).
		deletedInRun[config.Canonical(p.Path)] = true
		// Full audit enrichment from the fresh facts (round-1: the line
		// shape's fields were all dead) + capped manifest for non-clean
		// deletions (spec: gone is never contents unknown).
		result := auditlog.Line{Event: "result", Path: p.Path, Mode: mode, SizeBytes: p.SizeBytes,
			Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, Quarantine: nil}
		if rv.Git != nil {
			result.Branch = rv.Git.Branch
			result.Dirty, result.Untracked = rv.Git.Dirty, rv.Git.Untracked
			result.Stashes, result.Ignored = rv.Git.Stashes, rv.Git.Ignored
			result.HeadSHA = rv.Git.HEAD
			if !rv.Git.LastCommit.IsZero() {
				result.LastCommitTs = rv.Git.LastCommit.Format(time.RFC3339)
			}
		}
		if p.ParentRepo != "" {
			result.ParentRepo = p.ParentRepo
		}
		for _, c := range cands {
			if c.entry.Path == p.Path {
				result.Origin = c.entry.Origin
			}
		}
		result.Manifest = rv.Manifest
		result.Residue = rv.Residue
		ok := true
		result.OK = &ok
		if rc := appendOrAbort(result); rc >= 0 {
			return rc
		}
		summary.Deleted = append(summary.Deleted, p.Path)
		summary.DeletedBytes += p.SizeBytes
	}

	freeAfter := auditlog.FreeBytes(stateDir)
	if freeAfter > freeBefore {
		summary.FreeGain = freeAfter - freeBefore // saturating: underflow observed live in round 1
	}
	if !*asJSON {
		fmt.Fprintf(stdout, "deleted %d dirs (%.1f GB), excluded %d (%.1f GB below floor), skipped %d (%.1f GB): %s\n",
			len(summary.Deleted), float64(summary.DeletedBytes)/(1<<30),
			len(below), float64(sumExcluded(below))/(1<<30),
			len(summary.Skipped), float64(summary.SkippedBytes)/(1<<30), summarizeSkips(summary.Skipped))
	} else {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
	}
	if len(summary.Skipped) > 0 {
		return applycmd.ExitWithSkips
	}
	return applycmd.ExitOK
}

func sumExcluded(below []applycmd.ExcludedRef) int64 {
	var t int64
	for _, b := range below {
		t += b.Size
	}
	return t
}

func pathsOf(plan []applycmd.PlanEntry) []string {
	out := make([]string, len(plan))
	for i, p := range plan {
		out[i] = p.Path
	}
	return out
}

func widenedPaths(plan []applycmd.PlanEntry) []string {
	var out []string
	for _, p := range plan {
		if p.Widened {
			out = append(out, p.Path)
		}
	}
	return out
}

func summarizeSkips(skips []applycmd.SkippedPath) string {
	if len(skips) == 0 {
		return "none"
	}
	counts := map[string]int{}
	for _, s := range skips {
		counts[s.Why]++
	}
	var parts []string
	for why, n := range counts {
		parts = append(parts, fmt.Sprintf("%d %s", n, why))
	}
	return strings.Join(parts, ", ")
}

// cmdHold / cmdUnhold / cmdHolds implement the pin lifecycle.
func cmdHold(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hold", flag.ContinueOnError)
	fs.SetOutput(stderr)
	forStr := fs.String("for", "720h", "hold duration (Go duration; default 30d)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: reap hold PATH [--for DUR]")
		return ExitUsage
	}
	dur, err := time.ParseDuration(*forStr)
	if err != nil || dur <= 0 {
		fmt.Fprintf(stderr, "reap hold: bad --for %q\n", *forStr)
		return ExitUsage
	}
	stateDir, _ := config.StateDir()
	lock, err := applycmd.Lock(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap hold: %v\n", err)
		return ExitState
	}
	defer lock.Close()
	hf, err := applycmd.ReadHoldsSnapshotStrict(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap hold: %v\n", err)
		return ExitState
	}
	abs, _ := filepath.Abs(fs.Arg(0))
	hf[config.Canonical(abs)] = time.Now().Add(dur)
	if err := applycmd.WriteHolds(stateDir, hf); err != nil {
		fmt.Fprintf(stderr, "reap hold: %v\n", err)
		return ExitState
	}
	fmt.Fprintf(stdout, "%d hold(s) recorded\n", len(hf))
	return ExitOK
}

func cmdUnhold(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("unhold", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: reap unhold PATH")
		return ExitUsage
	}
	stateDir, _ := config.StateDir()
	lock, err := applycmd.Lock(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap unhold: %v\n", err)
		return ExitState
	}
	defer lock.Close()
	hf := applycmd.ReadHoldsSnapshot(stateDir)
	abs, _ := filepath.Abs(fs.Arg(0))
	canonical := config.Canonical(abs)
	if _, ok := hf[canonical]; !ok {
		fmt.Fprintf(stderr, "reap unhold: no hold on %s\n", fs.Arg(0))
		return ExitUsage
	}
	delete(hf, canonical)
	if err := applycmd.WriteHolds(stateDir, hf); err != nil {
		fmt.Fprintf(stderr, "reap unhold: %v\n", err)
		return ExitState
	}
	fmt.Fprintf(stdout, "%d hold(s) recorded\n", len(hf))
	return ExitOK
}

func cmdHolds(args []string, stdout, stderr io.Writer) int {
	stateDir, _ := config.StateDir()
	hf := applycmd.ReadHoldsSnapshot(stateDir)
	asJSON := hasFlag(args, "--json")
	now := time.Now()
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		out := map[string]map[string]any{}
		for p, exp := range hf {
			days := int(now.Sub(exp).Hours() / 24 * -1)
			_, exists := os.Stat(p)
			out[p] = map[string]any{"expires": exp.Format(time.RFC3339), "daysRemaining": days, "pathExists": exists == nil}
		}
		if err := enc.Encode(out); err != nil {
			return ExitState
		}
		return ExitOK
	}
	if len(hf) == 0 {
		fmt.Fprintln(stdout, "no holds")
		return ExitOK
	}
	for p, exp := range hf {
		status := ""
		if _, err := os.Stat(p); os.IsNotExist(err) {
			status = "  (path gone)"
		}
		fmt.Fprintf(stdout, "%s  expires in %dd%s\n", p, int(time.Until(exp).Hours()/24), status)
	}
	return ExitOK
}
