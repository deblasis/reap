package cli

import (
	"encoding/json"
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
	cfg                                        config.Config
	roots                                      []string
	noGH, noJJ                                 bool
	prHeads                                    *ghx.PRHeads
	useGit, useJJ                              bool
	protectExpanded                            []string
	holds                                      map[string]bool
	remoteStale                                time.Duration
	gitBudget, jjBudget, ghBudget, fetchBudget time.Duration
}

func newScanCore(args []string, stderr io.Writer) (*scanCore, int) {
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
	core := &scanCore{cfg: cfg, noGH: hasFlag(args, "--no-gh"), noJJ: hasFlag(args, "--no-jj")}
	core.gitBudget, core.jjBudget, core.ghBudget, core.fetchBudget, err = cfg.Thresholds.Budgets()
	if err != nil {
		fmt.Fprintf(stderr, "reap: %v\n", err)
		return nil, ExitState
	}
	// --roots narrowing (validated against configured roots)
	var rootsFlag []string
	for i, a := range args {
		if a == "--roots" && i+1 < len(args) {
			rootsFlag = append(rootsFlag, args[i+1])
		}
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
	holds, err := loadHolds(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap: %v\n", err)
		return nil, ExitState
	}
	core.holds = holds
	core.remoteStale = time.Duration(cfg.Thresholds.RemoteStaleHours) * time.Hour
	return core, ExitOK
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
}

// run walks the roots and verdicts every candidate (the scan core minus
// rendering; scan renders, plan/apply select).
func (c *scanCore) run(now time.Time) ([]candidate, []string) {
	infos := walk.Roots(c.roots, now, 8)
	var unreadableRoots []string
	var out []candidate
	type job struct {
		info walk.DirInfo
		res  chan candidate
	}
	jobs := make(chan job)
	var collect chan candidate
	collect = make(chan candidate, len(infos))
	go func() {
		for range jobs {
		}
	}()
	_ = collect
	// Sequential is fine for correctness here; the scan command keeps its
	// parallel pool for display speed. plan/apply re-verify per path anyway.
	for _, info := range infos {
		if info.Root == info.Path {
			unreadableRoots = append(unreadableRoots, info.Path)
			continue
		}
		if info.IsReparse {
			continue // KEEP rails never enter plans
		}
		e, v, cls := c.build(info, now)
		out = append(out, candidate{entry: e, vd: v, cls: cls})
	}
	return out, unreadableRoots
}

func (c *scanCore) build(info walk.DirInfo, now time.Time) (report.Entry, verdict.Verdict, classify.Info) {
	e := report.Entry{
		Path:         info.Path,
		Zone:         info.Root,
		SizeBytes:    info.Bytes,
		SizePartial:  info.Partial,
		LastActivity: &info.MaxMtime,
		AgeDays:      int(now.Sub(info.MaxMtime).Hours() / 24),
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
	return e, v, cls
}

// resolvePlan applies the SAFE-default + include/exclude/override selection.
func resolvePlan(cands []candidate, include, exclude, overrideManual []string) ([]applycmd.PlanEntry, []string, error) {
	var plan []applycmd.PlanEntry
	var excluded []string
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
		take := false
		widened := false
		switch {
		case c.vd.Verdict == verdict.Safe:
			take = true
		case inc[c.vd.Code] && c.vd.Verdict == verdict.Manual && c.vd.BlockedClassFact == "":
			take, widened = true, true
		case ovr[config.Canonical(c.entry.Path)] && c.vd.Verdict == verdict.Manual && c.vd.BlockedClassFact == "":
			take = true
		}
		if !take {
			continue
		}
		if exc[c.vd.Code] {
			excluded = append(excluded, c.entry.Path)
			continue
		}
		// Judgment-class ignorance codes can never be widened into (the
		// class maps say so; a code that resolves only to ignorance rows is
		// a usage error naming it).
		if widened && isIgnoranceCode(c.vd.Code) {
			return nil, nil, fmt.Errorf("--include %s selects ignorance-class rows (never deletable); the paths are held: %s", c.vd.Code, c.entry.Path)
		}
		plan = append(plan, applycmd.PlanEntry{
			Path: c.entry.Path, Verdict: c.vd.Verdict, Code: c.vd.Code,
			SizeBytes: c.entry.SizeBytes, Widened: widened, Kind: c.cls.Kind, Parent: c.cls.ParentRepo,
		})
	}
	// Validate include codes that matched nothing deletable: a code whose
	// every match was BLOCKED-class must error by name (spec).
	for _, code := range include {
		used := false
		for _, p := range plan {
			if p.Code == code {
				used = true
			}
		}
		if !used {
			blockedMatch := false
			for _, c := range cands {
				if c.vd.Code == code && c.vd.BlockedClassFact != "" {
					blockedMatch = true
				}
			}
			if blockedMatch {
				return nil, nil, fmt.Errorf("--include %s matched only BLOCKED-class paths (never deletable)", code)
			}
		}
	}
	return plan, excluded, nil
}

func isIgnoranceCode(code string) bool {
	switch code {
	case "facts-unavailable", "state-unreadable", "remote-stale", "jj-remote-stale", "gh-unavailable", "unknown-kind":
		return true
	}
	return false
}

// cmdPlan implements both `reap plan` and `reap apply --dry-run`
// (byte-identical output is the spec's tie between them).
func cmdPlan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootsFlag := multiFlag{}
	fs.Var(&rootsFlag, "roots", "narrow to these configured roots")
	fs.Float64("min-gb", 0, "planning floor (GB)")
	fs.Bool("no-gh", false, "skip the open-PR fact (weakens verdicts)")
	fs.Bool("no-jj", false, "skip jj facts (weakens verdicts)")
	include := multiFlag{}
	fs.Var(&include, "include", "widen into a judgment-class MANUAL code (repeatable)")
	exclude := multiFlag{}
	fs.Var(&exclude, "exclude", "narrow out a reason code (repeatable)")
	asJSON := fs.Bool("json", false, "emit the machine schema")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	core, code := newScanCore(args, stderr)
	if core == nil {
		return code
	}
	now := time.Now()
	cands, _ := core.run(now)
	plan, _, err := resolvePlan(cands, include, exclude, nil)
	if err != nil {
		fmt.Fprintf(stderr, "reap plan: %v\n", err)
		return ExitUsage
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		type planJSON struct {
			Generated string               `json:"generated"`
			Planned   []applycmd.PlanEntry `json:"planned"`
		}
		if err := enc.Encode(planJSON{Generated: now.Format(time.RFC3339), Planned: plan}); err != nil {
			return ExitState
		}
		return ExitOK
	}
	var total int64
	for _, p := range plan {
		total += p.SizeBytes
	}
	fmt.Fprintf(stdout, "reap will permanently delete %d directories, %.1f GB logical (not recycled)\n", len(plan), float64(total)/(1<<30))
	for _, p := range plan {
		fmt.Fprintf(stdout, "%8.1f GB  %s  [%s]\n", float64(p.SizeBytes)/(1<<30), p.Path, p.Code)
	}
	fmt.Fprintln(stdout, "dry-run: nothing will be deleted")
	return ExitOK
}

// cmdApply implements `reap apply`.
func cmdApply(args []string, stdout, stderr io.Writer, stdin *os.File) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootsFlag := multiFlag{}
	fs.Var(&rootsFlag, "roots", "narrow to these configured roots")
	fs.Float64("min-gb", 0, "planning floor (GB)")
	fs.Bool("no-gh", false, "skip the open-PR fact (weakens verdicts)")
	fs.Bool("no-jj", false, "skip jj facts (weakens verdicts)")
	include := multiFlag{}
	fs.Var(&include, "include", "widen into a judgment-class MANUAL code (repeatable)")
	exclude := multiFlag{}
	fs.Var(&exclude, "exclude", "narrow out a reason code (repeatable)")
	overrideManual := multiFlag{}
	fs.Var(&overrideManual, "override-manual", "relax the MANUAL gate for exactly this path (repeatable)")
	asJSON := fs.Bool("json", false, "emit the machine schema")
	yes := fs.Bool("yes", false, "confirm non-interactively")
	dryRun := fs.Bool("dry-run", false, "print the re-verified plan and exit (byte-identical to plan)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	stateDir, err := config.StateDir()
	if err != nil {
		fmt.Fprintf(stderr, "reap apply: %v\n", err)
		return ExitState
	}
	core, code := newScanCore(args, stderr)
	if core == nil {
		return code
	}
	now := time.Now()
	cands, _ := core.run(now)
	plan, excluded, err := resolvePlan(cands, include, exclude, overrideManual)
	if err != nil {
		fmt.Fprintf(stderr, "reap apply: %v\n", err)
		return ExitUsage
	}

	// Preflight: min-free-mb floor (audit growth + rotation headroom).
	minFree := uint64(core.cfg.Thresholds.MinFreeMB) << 20
	free := auditlog.FreeBytes(stateDir)
	widenedCount := 0
	for _, p := range plan {
		if p.Widened {
			widenedCount++
		}
	}
	proceed, ccode := applycmd.Confirm(stdout, stdin, plan, widenedCount, minFree, free, applycmd.Options{
		DryRun: *dryRun, Yes: *yes, JSON: *asJSON,
	})
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

	// Lineage: children before parents; parent whose live children are
	// outside the set gets skipped.
	ordered, parentSkips := applycmd.OrderChildrenFirst(plan)
	summary := applycmd.Summary{RunID: runID, Planned: pathsOf(plan), Excluded: excluded}
	for _, s := range parentSkips {
		summary.Skipped = append(summary.Skipped, s)
	}

	d := applycmd.Deleter{
		Git: gitx.Runner{GitBudget: core.gitBudget, FetchBudget: core.fetchBudget},
		JJ:  jjx.Runner{Budget: core.jjBudget},
	}
	hardAbort := ""
	for _, p := range ordered {
		intent := auditlog.Line{
			Event: "intent", Path: p.Path, Kind: string(p.Kind), SizeBytes: p.SizeBytes,
			Verdict: p.Verdict, ReasonCode: p.Code,
			Quarantine: nil,
		}
		if err := log.Append(intent); err != nil {
			fmt.Fprintf(stderr, "reap apply: HARD ABORT: %v\n", err)
			return ExitState
		}
		skipWhy, fresh := applycmd.Reverify(p.Path, applycmd.Options{}, core.cfg, d, core.protectExpanded, core.holds)
		if skipWhy != "" {
			if strings.HasPrefix(skipWhy, "PROBE-STRANDED:") {
				fmt.Fprintf(stderr, "reap apply: HARD ABORT: %s\n", skipWhy)
				return ExitState
			}
			summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{Path: p.Path, Why: skipWhy})
			ok := false
			_ = log.Append(auditlog.Line{Event: "skip", Path: p.Path, SkipWhy: skipWhy, Verdict: fresh.Verdict, ReasonCode: fresh.Code, OK: &ok, Quarantine: nil})
			continue
		}
		mode, err := applycmd.Delete(p.Path, classify.Dir(p.Path), d, log, intent)
		if err != nil {
			ok := false
			_ = log.Append(auditlog.Line{Event: "result", Path: p.Path, Mode: mode, OK: &ok, Quarantine: nil})
			fmt.Fprintf(stderr, "reap apply: deletion failed: %s: %v\n", p.Path, err)
			return applycmd.ExitDeleteFail
		}
		ok := true
		if err := log.Append(auditlog.Line{Event: "result", Path: p.Path, Mode: mode, OK: &ok, SizeBytes: p.SizeBytes, Quarantine: nil}); err != nil {
			fmt.Fprintf(stderr, "reap apply: HARD ABORT: %v\n", err)
			return ExitState
		}
		summary.Deleted = append(summary.Deleted, p.Path)
		if p.Widened {
			summary.Widened = append(summary.Widened, p.Path)
		}
	}

	freeAfter := auditlog.FreeBytes(stateDir)
	summary.FreeGain = freeAfter - freeBefore
	_ = log.Append(auditlog.Line{Event: "envelope", Planned: len(plan), Deleted: len(summary.Deleted),
		Skipped: len(summary.Skipped), FreeBefore: freeBefore, FreeAfter: freeAfter, Quarantine: nil})
	_ = hardAbort

	fmt.Fprintf(stdout, "deleted %d dirs, excluded %d (below floor), skipped %d: %s\n",
		len(summary.Deleted), len(excluded), len(summary.Skipped), summarizeSkips(summary.Skipped))
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
	}
	if len(summary.Skipped) > 0 {
		return applycmd.ExitWithSkips
	}
	return applycmd.ExitOK
}

func pathsOf(plan []applycmd.PlanEntry) []string {
	out := make([]string, len(plan))
	for i, p := range plan {
		out[i] = p.Path
	}
	return out
}

func summarizeSkips(skips []applycmd.SkippedPath) string {
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
	hf := applycmd.ReadHoldsSnapshot(stateDir)
	if hf == nil {
		hf = map[string]time.Time{}
	}
	abs, _ := filepath.Abs(fs.Arg(0))
	hf[config.Canonical(abs)] = time.Now().Add(dur)
	return writeHolds(stateDir, hf, stdout)
}

func cmdUnhold(args []string, stdout, stderr io.Writer) int {
	stateDir, _ := config.StateDir()
	lock, err := applycmd.Lock(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap unhold: %v\n", err)
		return ExitState
	}
	defer lock.Close()
	hf := applycmd.ReadHoldsSnapshot(stateDir)
	abs, _ := filepath.Abs(args[len(args)-1])
	delete(hf, config.Canonical(abs))
	return writeHolds(stateDir, hf, stdout)
}

func writeHolds(stateDir string, hf map[string]time.Time, stdout io.Writer) int {
	raw, err := json.MarshalIndent(hf, "", "  ")
	if err != nil {
		return ExitState
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return ExitState
	}
	if err := config.AtomicWrite(filepath.Join(stateDir, "holds.json"), raw, 0o644); err != nil {
		return ExitState
	}
	fmt.Fprintf(stdout, "%d hold(s) recorded\n", len(hf))
	return ExitOK
}

func cmdHolds(args []string, stdout, stderr io.Writer) int {
	stateDir, _ := config.StateDir()
	hf := applycmd.ReadHoldsSnapshot(stateDir)
	asJSON := hasFlag(args, "--json")
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		out := map[string]map[string]any{}
		for p, exp := range hf {
			days := int(time.Until(exp).Hours() / 24)
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
