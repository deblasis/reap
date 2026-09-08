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
	"github.com/deblasis/reap/internal/dedupe"
	"github.com/deblasis/reap/internal/ghx"
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/jjx"
	"github.com/deblasis/reap/internal/quarantine"
	"github.com/deblasis/reap/internal/report"
	"github.com/deblasis/reap/internal/verdict"
	"github.com/deblasis/reap/internal/walk"
)

// scanCore is the shared scan/plan/apply pipeline: walk, facts, verdicts.
// The spec's invariant  -  plan/apply always run full-strength over the set,
// same flags as scan  -  falls out of sharing one implementation.
type scanCore struct {
	cfg             config.Config
	roots           []string
	noGH, noJJ      bool
	prHeads         *ghx.PRHeads
	useGit, useJJ   bool
	protectExpanded []string
	holds           map[string]bool
	// incodaLive: canonical live-incoda dirs (M4 enrichment; ACTIVE rail
	// parity with the scan display pipeline).
	incodaLive map[string]bool
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
	// incoda attribution (M4): the same BOTH-trigger live set the scan
	// display builds (held tickets incl pure ones + open events in the
	// active-hours window). The records half of the snapshot is the scan
	// table's 'last:' enrichment source; the plan pipeline does not render
	// it (its own layout), so it is dropped here.
	core.incodaLive, _ = incodaSnapshot(time.Duration(cfg.Thresholds.ActiveHours) * time.Hour)
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
		if f.Deregistered && cls.Kind == classify.KindJJWorkspace {
			// The forget-then-rm crash shape, in the SHARED pipeline (round
			// 10: round 9 wired only the scan display, leaving the carve-out
			// unreachable here while the hint advertised it). KEEP rails
			// first, then the orphaned-workspace row. The FLAVOR rides the
			// verdict so every copy site (refusal, hardened confirm, intent
			// residue) can say 'parent alive, deregistered' instead of the
			// false 'parent gone'.
			in.Kind = classify.KindJJWorkspaceOrphaned
			in.GitBackend = false
			in.JJ = nil
			in.Held = anyHoldUnder(c.holds, info.Path)
			in.Protected, _ = config.MatchProtect(info.Path, c.protectExpanded)
			in.PRHeads = c.prHeads
			v := verdict.Decide(in)
			v.Flavor = verdict.FlavorDeregistered
			if v.Code == "orphaned-workspace" {
				v.Reason = "deregistered workspace (parent alive, this dir is out of its registry)"
				v.Hint = "deregistered workspace (parent alive, this dir is out of its registry); reap apply --override-manual asks a TTY-only hardened confirm"
			}
			e.Verdict, e.ReasonCode, e.Reason, e.Hint = v.Verdict, v.Code, v.Reason, v.Hint
			e.Kind = string(classify.KindJJWorkspaceOrphaned)
			e.Held = in.Held
			e.OrphanedCarveOut = v.OrphanedCarveOut
			e.BlockedClassFact = v.BlockedClassFact
			return e, v, classify.Info{Kind: classify.KindJJWorkspaceOrphaned}, nil
		}
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
	in.IncodaLive = anyIncodaUnder(c.incodaLive, info.Path)
	in.Held = anyHoldUnder(c.holds, info.Path)
	in.Protected, _ = config.MatchProtect(info.Path, c.protectExpanded)
	v := verdict.Decide(in)
	e.Verdict, e.ReasonCode, e.Reason, e.Hint = v.Verdict, v.Code, v.Reason, v.Hint
	e.Held = in.Held
	e.BlockedClassFact = v.BlockedClassFact
	e.OrphanedCarveOut = v.OrphanedCarveOut
	e.OpenPR = v.OpenPRSlug != ""
	// The shadowed detail, verdict-agnostic (round 14, mirroring the scan
	// pipeline: KEEP/MANUAL rows carrying a shadowed BLOCKED fact suffix it;
	// a BLOCKED row does not suffix itself).
	if v.BlockedClassFact != "" && v.Verdict != verdict.Blocked {
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
func resolvePlan(cands []candidate, include, exclude, overrideManual []string, minGB float64, carveOut bool) (plan []applycmd.PlanEntry, below []applycmd.ExcludedRef, excludedByCode []string, err error) {
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
			counts := countsFor(c.vd.Flavor)
			if c.vd.BlockedClassFact != "" {
				counts = c.vd.BlockedClassFact + countsSuffixFor(c.vd.Flavor)
			}
			// The carve-out is --override-manual ONLY, always (spec: '--include
			// can never reach carve-out dirs'): --include is a code-level blast
			// radius over every orphan in the roots; the override names ONE
			// path. Even the TTY re-resolve refuses the include arm.
			if !carveOut || inc[c.vd.Code] {
				return nil, nil, nil, &carveOutRefusal{path: c.entry.Path, counts: counts}
			}
			// The carve-out, unlocked only for a live TTY (the hardened
			// confirm + capped plain-copy snapshot happen in cmdApply).
			take, widened = true, true
		case inc[c.vd.Code] && c.vd.Verdict == verdict.Manual && c.vd.BlockedClassFact == "":
			// The widening gate the spec pins at RESOLUTION time: only
			// judgment-class MANUALs may widen. Ignorance rows (unread
			// state, stale remote, tool failure) must refuse HERE with the
			// side-door copy  -  advertising them as deletable and skipping
			// them at re-verify is exactly the "output advertises a gate
			// the tool will refuse" shape the spec forbids.
			if !verdict.IsJudgmentCode(c.vd.Code) {
				return nil, nil, nil, fmt.Errorf("%s is %s: an unread-state row (the fact is unavailable, not judged); overriding unread state is a side door around the cardinal rule; fix the tool or rerun scan, then widen on the row it shows",
					c.entry.Path, c.vd.Code)
			}
			take, widened = true, true
		case ovr[config.Canonical(c.entry.Path)] && c.vd.Verdict == verdict.Manual && c.vd.BlockedClassFact == "":
			if !verdict.IsJudgmentCode(c.vd.Code) {
				return nil, nil, nil, fmt.Errorf("%s is %s: an unread-state row (the fact is unavailable, not judged); overriding unread state is a side door around the cardinal rule; fix the tool or rerun scan, then widen on the row it shows",
					c.entry.Path, c.vd.Code)
			}
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
		if c.vd.OrphanedCarveOut && c.vd.BlockedClassFact != "" {
			pe.OrphanCounts = c.vd.BlockedClassFact
		}
		pe.Flavor = c.vd.Flavor
		if widened && c.vd.BlockedClassFact != "" {
			// Shadowed BLOCKED facts ride the plan row (spec: residue noted
			// in the plan row)  -  the deletion is accepted WITH this overlap.
			pe.Residue = c.vd.BlockedClassFact
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
// non-interactive with --yes; a live TTY re-resolves with the carve-out
// from non-TTY apply --yes, counts always in the message (spec interim).
type carveOutRefusal struct{ path, counts string }

func (e *carveOutRefusal) Error() string {
	return fmt.Sprintf("%s is an orphaned carve-out row (%s): deletable only via reap apply --override-manual <path> on a live TTY (hardened confirm + capped plain-copy quarantine); --include can never reach carve-out dirs", e.path, e.counts)
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
	// The plan-time hardlink pass (spec: plan/apply/discard): logical vs
	// expected reclaim, with the skipped-pass caveat.
	planReclaim := dedupe.NewCounter(50000)
	for _, p := range plan {
		planReclaim.Add(p.Path)
	}
	expected := planReclaim.Expected
	caveat := ""
	if planReclaim.Over() {
		expected = total
		caveat = "; hardlink pass skipped, logical only"
	}
	fmt.Fprintf(w, "reap will permanently delete %d directories, logical %.1f GB, expected reclaim ~%.1f GB (not recycled%s)", len(plan), float64(total)/(1<<30), float64(expected)/(1<<30), caveat)
	if len(widened) > 0 {
		fmt.Fprintf(w, "; %d widened via %s", len(widened), strings.Join(dedupeStrings(widened), ","))
	}
	fmt.Fprintln(w)
	var orphaned []applycmd.PlanEntry
	for _, p := range plan {
		if p.Orphaned {
			orphaned = append(orphaned, p)
			continue
		}
		row := fmt.Sprintf("%8.1f GB  %s  [%s]", float64(p.SizeBytes)/(1<<30), p.Path, p.Code)
		if p.Residue != "" {
			row += "  (residue: " + p.Residue + ")"
		}
		fmt.Fprintln(w, row)
	}
	// The carve-out rows render as their own OVERRIDDEN-ORPHANED section
	// (spec: a distinct section, never mixed into the ordinary rows).
	if len(orphaned) > 0 {
		fmt.Fprintln(w, "OVERRIDDEN-ORPHANED (TTY-only hardened confirm; capped plain-copy quarantine first):")
		for _, p := range orphaned {
			counts := countsFor(p.Flavor)
			if p.OrphanCounts != "" {
				counts = p.OrphanCounts + countsSuffixFor(p.Flavor)
			}
			fmt.Fprintf(w, "%8.1f GB  %s  [%s]  (%s)\n", float64(p.SizeBytes)/(1<<30), p.Path, p.Code, counts)
		}
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
	plan, below, byCodeExcl, err := resolvePlan(cands, include, exclude, nil, *minGB, false)
	if err == nil {
		if dropped := droppedWidenings(cands, include, nil, plan, below, byCodeExcl); len(dropped) > 0 {
			for _, d := range dropped {
				fmt.Fprintf(stderr, "reap plan: %s\n", d)
			}
			return ExitUsage
		}
	}
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
	plan, below, byCode, err := resolvePlan(cands, include, exclude, overrideManual, *minGB, false)
	carveOutActive := false
	if err != nil {
		var co *carveOutRefusal
		if errors.As(err, &co) {
			if !applycmd.IsTerminal(stdin, stdout) {
				// Agents are barred from the carve-out: the hardened
				// confirm is TTY-only, --yes does not unlock it, and the
				// non-TTY band is 121 regardless of --yes (spec: 'non-TTY
				// (agents) exits 121').
				fmt.Fprintf(stderr, "reap apply: %v\n", co)
				return applycmd.ExitNotTTY
			}
			// A live TTY: re-resolve WITH the carve-out; the hardened
			// confirm (below, after the plan confirm) gates the deletion.
			plan, below, byCode, err = resolvePlan(cands, include, exclude, overrideManual, *minGB, true)
			if err != nil {
				fmt.Fprintf(stderr, "reap apply: %v\n", err)
				return ExitUsage
			}
			carveOutActive = true
		} else {
			fmt.Fprintf(stderr, "reap apply: %v\n", err)
			return ExitUsage
		}
	}
	// The refusal pass: a --override-manual path (or --include code) that
	// matched a candidate but was not taken is a NAMED error carrying the
	// shadowed fact  -  never a silent drop that prints "0 directories" and
	// exits 0 (the round-6 spec finding).
	if dropped := droppedWidenings(cands, include, overrideManual, plan, below, byCode); len(dropped) > 0 {
		for _, d := range dropped {
			fmt.Fprintf(stderr, "reap apply: %s\n", d)
		}
		return ExitUsage
	}

	// The dry-run tie: delegate to the exact plan renderer  -  byte-identical
	// in text AND json (round-1 blocker).
	if *dryRun {
		if *asJSON {
			return renderPlanJSON(stdout, now, plan, below)
		}
		renderPlanText(stdout, plan, below, planWidenedCodes(plan), collectExpired(cands))
		return ExitOK
	}

	// Preflight floor: a refusal, not a print. Carve-out runs raise the
	// floor to cap x margin (the spec: a confirmed snapshot is never
	// replaced by a silent no-snapshot deletion  -  the quarantine write
	// itself needs the headroom).
	minFree := uint64(core.cfg.Thresholds.MinFreeMB) << 20
	if carveOutActive {
		raised := uint64(float64(core.cfg.Thresholds.QuarantineCapGB) * core.cfg.Thresholds.QuarantineMargin * float64(1<<30))
		if raised > minFree {
			minFree = raised
		}
	}
	free := auditlog.FreeBytes(stateDir)
	widened := planWidenedCodes(plan)
	proceed, ccode := applycmd.Confirm(stdout, stdin, plan, widened, minFree, free, applycmd.Options{Yes: *yes, ErrOut: stderr})
	if !proceed {
		return ccode
	}
	// The carve-out's own hardened confirm: a second, explicit gate that
	// --yes never satisfies, naming each orphan with KNOWABLE counts
	// (parent present but broken) vs unknowable ones (parent gone), the
	// stale gitdir where it resolves, and the capped plain-copy quarantine
	// taken before its deletion.
	if carveOutActive {
		for _, p := range plan {
			if !p.Orphaned {
				continue
			}
			counts := countsFor(p.Flavor)
			if p.OrphanCounts != "" {
				counts = p.OrphanCounts + countsSuffixFor(p.Flavor)
			}
			gitdir := ""
			if p.ParentRepo != "" {
				gitdir = fmt.Sprintf("; stale gitdir: %s", p.ParentRepo)
			}
			fmt.Fprintf(stdout, "  ORPHANED %s (%.1f GB): %s%s; a capped plain-copy quarantine is taken first\n",
				p.Path, float64(p.SizeBytes)/(1<<30), counts, gitdir)
		}
		fmt.Fprint(stdout, "carve-out deletion (recovery = the plain copy only). Type y to confirm: ")
		var answer string
		if _, aerr := fmt.Fscanln(stdin, &answer); aerr != nil {
			fmt.Fprintln(stdout, "\ndeclined")
			return ExitOK
		}
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Fprintln(stdout, "declined")
			return ExitOK
		}
	}

	// Exclusive lock for the whole run. The runId is minted FIRST so the
	// lock body names the real run; holds are RE-READ under the lock  -  a
	// hold that landed while the operator sat at the confirm prompt (the
	// lock was free then) must reach re-verify: holds beat every flag.
	runID := auditlog.NewRunID()
	lock, err := applycmd.Lock(stateDir, runID)
	if err != nil {
		fmt.Fprintf(stderr, "reap apply: %v\n", err)
		return ExitState
	}
	defer lock.Close()

	// The ledger opens BEFORE the under-lock gates (round 5: the holds
	// re-read and incoda re-probe aborts previously returned traceless -
	// a CONFIRMED run that stopped for a mid-window reason left no session
	// record at all, live-proven by the panel on a 300-dir run).
	log, err := auditlog.Open(stateDir, runID)
	if err != nil {
		fmt.Fprintf(stderr, "reap apply: %v\n", err)
		return ExitState
	}
	freeBefore := auditlog.FreeBytes(stateDir)
	// A gate abort still leaves its trace: one result line naming the
	// path and cause, then the envelope (every planned path skipped by
	// the abort - planned N, deleted 0 is the reconciled truth).
	gateAbort := func(path, cause string) int {
		ok := false
		_ = log.Append(auditlog.Line{Event: "result", Path: path, OK: &ok, Quarantine: nil, Residue: cause})
		_ = log.Append(auditlog.Line{Event: "envelope", Planned: len(plan), Deleted: 0,
			Skipped: len(plan), FreeBefore: freeBefore, FreeAfter: auditlog.FreeBytes(stateDir), Quarantine: nil})
		return ExitState
	}

	freshHolds := applycmd.ReadHoldsSnapshot(stateDir)
	for h := range freshHolds {
		core.holds[h] = true
	}
	for _, p := range plan {
		if applycmd.PathHeld(core.holds, p.Path) {
			fmt.Fprintf(stderr, "reap apply: %s: held by user DURING the confirm window (reap hold landed mid-run); rerun apply if this is unexpected\n", p.Path)
			return gateAbort(p.Path, "held by user DURING the confirm window (reap hold landed mid-run); run aborted, nothing deleted")
		}
	}
	// The incoda re-probe, hold-parity: the live set was built at scan
	// time, before the (unbounded) confirm window - a ticket taken on a
	// planned dir in that window is invisible to the match gate otherwise,
	// and an enqueued-not-yet-writing job touches no files and holds no
	// handles, so the tripwire and rename probe cannot see it either. One
	// fresh sweep under the lock; a hit aborts the run naming the dir
	// (the same named-abort shape as the holds re-read - the job may be
	// the reason the operator ran apply in the first place; round 4 fixed
	// the copy: nothing is skipped, the whole run stops before any
	// deletion; round 5 made the abort legible on the ledger).
	freshLive := confirmReprobeLive(time.Duration(core.cfg.Thresholds.ActiveHours) * time.Hour)
	for _, p := range plan {
		if anyIncodaUnder(freshLive, p.Path) {
			fmt.Fprintf(stderr, "reap apply: %s: live incoda ticket at/under it DURING the confirm window (a job landed mid-run); run aborted, nothing deleted; rerun apply when the job finishes\n", p.Path)
			return gateAbort(p.Path, "live incoda ticket at/under it DURING the confirm window (a job landed mid-run); run aborted, nothing deleted")
		}
	}

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
	carveOutFailed := false // any 125-class carve-out quarantine failure
	applyReclaim := dedupe.NewCounter(50000)
	for _, p := range ordered {
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
		// The intent line lands HERE: after re-verify (so it carries the
		// fresh residue and, for carve-out rows, the hardened-confirm
		// record the spec pins) but BEFORE any mutation  -  the write-ahead
		// contract is intent-before-DELETION, and the skip lines above
		// already cover the refusals. Carve-out rows write their intent
		// AFTER the plain-copy switch so the consent OUTCOME (snapshot
		// taken vs over-cap accepted) rides the same line  -  a crash between
		// accept and Delete must be distinguishable from a plain-copy run.
		writeIntent := func(extraResidue string, manifest []byte) int {
			intent := auditlog.Line{
				Event: "intent", Path: p.Path, Kind: p.Kind, SizeBytes: p.SizeBytes,
				Verdict: p.Verdict, ReasonCode: p.Code, Quarantine: nil,
				Manifest: manifest,
			}
			notes := []string{}
			if rv.Residue != "" {
				notes = append(notes, rv.Residue)
			}
			if len(rv.Nested) > 0 {
				notes = append(notes, "nested: "+strings.Join(rv.Nested, ", "))
			}
			if extraResidue != "" {
				notes = append(notes, extraResidue)
			}
			intent.Residue = strings.Join(notes, "; ")
			return appendOrAbort(intent)
		}
		if !p.Orphaned {
			// Manifest write-ahead for EVERY non-clean deletion (round 9:
			// carve-out rows had it; widened scratch/ignored/nested rows
			// are the same crash-window shape  -  'gone is never contents
			// unknown' rides the fsynced ledger, not the post-Delete line).
			intentManifest := []byte(nil)
			if p.Code != "clean-pushed" {
				intentManifest = rv.Manifest
			}
			if rc := writeIntent("", intentManifest); rc >= 0 {
				return rc
			}
		}
		// The carve-out rows: a capped plain-copy quarantine BEFORE the
		// deletion (the orphan has no git backend to bundle; the plain
		// copy is its only recovery). Over-cap is the operator's call via
		// the spec's Proceed prompt (deletion unrecoverable except for the
		// file manifest, mode=plain-copy-skipped-overcap); a FAILED copy
		// is a 125-band quarantine refusal with the dir untouched.
		var qPtrVal *string
		carveMode := ""
		if p.Orphaned {
			capBytes := int64(core.cfg.Thresholds.QuarantineCapGB * float64(1<<30))
			session := ""
			var qerr error
			for attempt := 0; attempt < 2; attempt++ {
				session = quarantine.FreshSessionDir(stateDir, p.Path, time.Now())
				_, qerr = quarantine.WritePlainCopy(session, p.Path, capBytes)
				if qerr == nil || !isSessionExistsErr(qerr) {
					break
				}
			}
			var tooLarge *quarantine.ErrTooLarge
			switch {
			case qerr == nil:
				qPtrVal = &session
				carveMode = "plain-copy"
				// Multi-orphan accounting (the R5 carryover): each copy
				// consumes the volume this run preflighted once  -  recheck
				// the audit floor before the next copy. A stop here is a
				// proper SKIP line with the taken session's pointer (the
				// copy exists on disk; the ledger must say where).
				if freeNow := auditlog.FreeBytes(stateDir); freeNow < minFree {
					fmt.Fprintf(stderr, "reap apply: free space fell below the floor mid-run (%d MB); stopping\n", freeNow>>20)
					ok := false
					if rc := appendOrAbort(auditlog.Line{Event: "skip", Path: p.Path,
						SkipWhy: applycmd.SkipSnapshotOvercap, OK: &ok, Quarantine: &session,
						Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code,
						Residue: "free space below floor after the plain copy; session kept",
					}); rc >= 0 {
						return rc
					}
					summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{
						Path: p.Path, Why: applycmd.SkipSnapshotOvercap, Note: "free space below floor after the plain copy (session kept)"})
					summary.SkippedBytes += p.SizeBytes
					carveOutFailed = true
					continue
				}
			case errors.As(qerr, &tooLarge):
				// The TTY-only over-cap consent (the carve-out is TTY-gated
				// by construction; --yes never reached this path). A decline
				// is a SKIP: visible in the summary and the exit-2 band,
				// never a silent machine-invisible non-deletion.
				need, cap, unit := float64(tooLarge.Need)/(1<<30), float64(tooLarge.Cap)/(1<<30), "GB"
				if tooLarge.Need < 1<<30 || tooLarge.Cap < 1<<30 {
					// GB would round the decision inputs away at small scales.
					need, cap, unit = float64(tooLarge.Need>>20), float64(tooLarge.Cap>>20), "MB"
				}
				fmt.Fprintf(stdout, "plain-copy snapshot exceeds the cap (needs %.1f %s, cap %.1f %s): deletion is unrecoverable except for the file manifest. Proceed? [y/N] ",
					need, unit, cap, unit)
				var answer string
				if _, aerr := fmt.Fscanln(stdin, &answer); aerr != nil || strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Fprintln(stdout, "declined")
					// A decline is a SKIP line (the enum cause: the cap
					// ended this deletion), visible in the summary and the
					// exit-2 band  -  never a silent machine-invisible
					// non-deletion.
					ok := false
					if rc := appendOrAbort(auditlog.Line{Event: "skip", Path: p.Path,
						SkipWhy: applycmd.SkipSnapshotOvercap, OK: &ok,
						Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, Quarantine: nil}); rc >= 0 {
						return rc
					}
					summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{
						Path: p.Path, Why: applycmd.SkipSnapshotOvercap, Note: "declined at the over-cap confirm"})
					summary.SkippedBytes += p.SizeBytes
					continue
				}
				carveMode = "plain-copy-skipped-overcap"
				// The consent lands on the ledger NOW, before the deletion
				// it authorizes (write-ahead: a crash after Delete must be
				// distinguishable from a deleted-with-snapshot run).
				ocCounts := countsFor(p.Flavor)
				if p.OrphanCounts != "" {
					ocCounts = p.OrphanCounts + countsSuffixFor(p.Flavor)
				}
				if rc := appendOrAbort(auditlog.Line{Event: "intent", Path: p.Path, Kind: p.Kind, SizeBytes: p.SizeBytes,
					Verdict: p.Verdict, ReasonCode: p.Code, Manifest: rv.Manifest,
					Residue: "hardened confirm shown (counts: " + ocCounts + "); over-cap consent accepted: recovery is the file manifest only"}); rc >= 0 {
					return rc
				}
			default:
				fmt.Fprintf(stderr, "reap apply: %s: carve-out quarantine failed: %v (dir untouched)\n", p.Path, qerr)
				ok := false
				if rc := appendOrAbort(auditlog.Line{Event: "result", Path: p.Path, OK: &ok,
					Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, Quarantine: nil,
					Residue: "carve-out plain-copy failed: " + qerr.Error()}); rc >= 0 {
					return rc
				}
				summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{
					Path: p.Path, Why: applycmd.SkipSnapshotOvercap, Note: "carve-out plain-copy failed"})
				summary.SkippedBytes += p.SizeBytes
				carveOutFailed = true
				continue
			}
		}
		// The orphaned intent (plain-copy success shape): the consent and
		// the taken-snapshot record land BEFORE the deletion. The counts
		// COMPOSE exactly as the prompt showed them (round 13: the ledger
		// recorded a different counts text than the confirm on this main
		// path - the prompt-vs-truth drift this sweep exists to kill).
		if p.Orphaned && carveMode == "plain-copy" {
			counts := countsFor(p.Flavor)
			if p.OrphanCounts != "" {
				counts = p.OrphanCounts + countsSuffixFor(p.Flavor)
			}
			if rc := writeIntent("hardened confirm shown (counts: "+counts+"); plain copy taken", rv.Manifest); rc >= 0 {
				return rc
			}
		}
		// Per-path ticket re-sweep (round 5): the confirm-window probe covers
		// only up to the lock; a large run spends minutes between that sweep
		// and this path's deletion, and an enqueued-not-yet-writing job
		// touches no files and holds no handles the tripwire or rename probe
		// can see. The sweep is cheap (one ReadDir + lock probes); a hit
		// skips the path with the session kept - the dir stands.
		if perPathTicketLive(p.Path) {
			ok := false
			note := "live or unknown-live incoda ticket at/under it (re-swept immediately before deletion); the dir is NOT deleted"
			fmt.Fprintf(stderr, "reap apply: %s: %s\n", p.Path, note)
			if rc := appendOrAbort(auditlog.Line{Event: "skip", Path: p.Path,
				SkipWhy: applycmd.SkipVerdictChanged, OK: &ok,
				Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, Quarantine: qPtrVal}); rc >= 0 {
				return rc
			}
			summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{
				Path: p.Path, Why: applycmd.SkipVerdictChanged, Note: note})
			summary.SkippedBytes += p.SizeBytes
			continue
		}
		// The dedupe pass walks each path now, before the deletion.
		applyReclaim.Add(p.Path)
		mode, err := applycmd.Delete(p.Path, rv.Class, d)
		if err != nil {
			// Deregistration failure is a deletion failure (spec's exit
			// band: 124, path named)  -  not a skip: skipWhy is the spec's
			// closed enum and the dir is still standing either way.
			ok := false
			_ = log.Append(auditlog.Line{Event: "result", Path: p.Path, Mode: mode, OK: &ok, Quarantine: qPtrVal})
			fmt.Fprintf(stderr, "reap apply: deletion failed: %s: %v\n", p.Path, err)
			return applycmd.ExitDeleteFail
		}
		// The in-run deletion set feeds the both-clean unlock (round-3: the
		// map existed but was never written  -  dead wiring).
		deletedInRun[config.Canonical(p.Path)] = true
		// Full audit enrichment from the fresh facts (round-1: the line
		// shape's fields were all dead) + capped manifest for non-clean
		// deletions (spec: gone is never contents unknown).
		result := auditlog.Line{Event: "result", Path: p.Path, Mode: mode, SizeBytes: p.SizeBytes,
			Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, Quarantine: qPtrVal}
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
		if carveMode == "plain-copy" {
			// The label must assert a copy that EXISTS: on an over-cap
			// accepted deletion there is no plain copy, and a false
			// "files only" presence is the inverse of the spec's
			// never-a-silent-absence rule (the round-6 spec finding).
			result.Mode = carveMode
			if result.Residue == "" {
				result.Residue = "carve-out plain copy: files only, no git objects"
			} else {
				result.Residue += "; carve-out plain copy: files only, no git objects"
			}
		} else if carveMode == "plain-copy-skipped-overcap" {
			result.Mode = carveMode
			if result.Residue == "" {
				result.Residue = "over-cap consent accepted: recovery is the file manifest only (no plain copy taken)"
			} else {
				result.Residue += "; over-cap consent accepted: recovery is the file manifest only (no plain copy taken)"
			}
		}
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
	// The deletion-set hardlink pass (spec: at plan/apply/discard time),
	// accumulated as each path is about to be deleted  -  one identity map
	// across the run, logical vs expected-reclaim both surfaced.
	if !*asJSON {
		expected := applyReclaim.Expected
		caveat := ""
		if applyReclaim.Over() {
			expected = summary.DeletedBytes
			caveat = " (logical; hardlink pass skipped)"
		}
		fmt.Fprintf(stdout, "deleted %d dirs (logical %.1f GB, expected reclaim ~%.1f GB%s), excluded %d (%.1f GB below floor), skipped %d (%.1f GB): %s\n",
			len(summary.Deleted), float64(summary.DeletedBytes)/(1<<30), float64(expected)/(1<<30), caveat,
			len(below), float64(sumExcluded(below))/(1<<30),
			len(summary.Skipped), float64(summary.SkippedBytes)/(1<<30), summarizeSkips(summary.Skipped))
	} else {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
	}
	if carveOutFailed {
		// A confirmed carve-out whose quarantine write failed is a
		// 125-band refusal (spec L420-422), never a silent exit 0 on a
		// run that deleted nothing (the round-3 spec finding).
		return applycmd.ExitQuarantine
	}
	if len(summary.Skipped) > 0 {
		return applycmd.ExitWithSkips
	}
	return applycmd.ExitOK
}

// droppedWidenings names every --include code and --override-manual path
// that MATCHED a candidate but was NOT taken for ELIGIBILITY reasons (KEEP,
// displayed-BLOCKED, shadowed MANUAL, ignorance)  -  the spec's refusal shape:
// a named usage error carrying the shadowed fact, never a silent drop.
// Rows the resolver DID take but excluded afterwards (below --min-gb,
// --exclude) are NOT refusals (they are the excluded buckets), and neither
// are SAFE rows given as override paths (already deletable, nothing widened
// was needed).
func droppedWidenings(cands []candidate, include, overrideManual []string, plan []applycmd.PlanEntry, below []applycmd.ExcludedRef, excludedByCode []string) []string {
	planned := map[string]bool{}
	for _, p := range plan {
		planned[config.Canonical(p.Path)] = true
	}
	excluded := map[string]bool{}
	for _, b := range below {
		excluded[config.Canonical(b.Path)] = true
	}
	for _, p := range excludedByCode {
		excluded[config.Canonical(p)] = true
	}
	inc := map[string]bool{}
	for _, c := range include {
		inc[c] = true
	}
	ovr := map[string]bool{}
	for _, p := range overrideManual {
		ovr[config.Canonical(p)] = true
	}
	var out []string
	for _, c := range cands {
		cp := config.Canonical(c.entry.Path)
		if excluded[cp] {
			continue // the excluded buckets are not refusals
		}
		fact := string(c.vd.Verdict) + "/" + c.vd.Code
		if c.vd.BlockedClassFact != "" {
			fact += " (shadowed fact: " + c.vd.BlockedClassFact + ")"
		}
		if ovr[cp] && !planned[cp] && c.vd.Verdict != verdict.Safe {
			out = append(out, fmt.Sprintf("%s: not override-eligible: %s", c.entry.Path, fact))
		}
		// --include of a code that matched this candidate but produced no
		// planned row: refuse naming the row  -  INCLUDING the shadowed case
		// (the displayed code differs from the include code; the BLOCKED
		// fact still rides this candidate).
		// The UNDERLYING SHAPE survives rails: a held/protected orphan
		// still matched --include orphaned-workspace by shape even though
		// the KEEP rail rewrote its displayed code (the round-10
		// held-shadow silent zero).
		shapeCode := ""
		switch c.cls.Kind {
		case classify.KindJJWorkspaceOrphaned:
			shapeCode = "orphaned-workspace"
		case classify.KindGitWorktreeOrphaned:
			shapeCode = "orphaned-worktree"
		}
		if (inc[c.vd.Code] || (shapeCode != "" && inc[shapeCode])) && !planned[cp] {
			out = append(out, fmt.Sprintf("%s: code %s matched but was not deletable: %s", c.entry.Path, c.vd.Code, fact))
		}
	}
	return out
}

// countsFor is the carve-out's counts line, flavor-aware: the
// deregistered workspace's parent is ALIVE one directory up, and the
// consent gate must not assert otherwise. The default flavor says
// "unreachable" rather than "gone": a broken-branch worktree's parent is
// often ALIVE with only the counts unknowable (the so755 class).
func countsFor(flavor string) string {
	if flavor == verdict.FlavorDeregistered {
		return "deregistered workspace (parent alive, this dir is out of its registry)"
	}
	return "counts unknowable, parent unreachable"
}

// countsSuffixFor qualifies KNOWABLE counts per flavor (round 12): the
// default orphan's parent is broken; the deregistered shape's is alive
// and merely no longer lists this dir.
func countsSuffixFor(flavor string) string {
	if flavor == verdict.FlavorDeregistered {
		return " (parent alive, this dir is out of its registry)"
	}
	return " (parent present but broken)"
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
	lock, err := applycmd.Lock(stateDir, "hold")
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
	lock, err := applycmd.Lock(stateDir, "unhold")
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
