package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/ghx"
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/jjx"
	"github.com/deblasis/reap/internal/report"
	"github.com/deblasis/reap/internal/verdict"
	"github.com/deblasis/reap/internal/walk"
)

// cmdScan implements `reap scan`: walk configured roots, collect facts,
// verdict every candidate, print the table (or --json). Exit 0 always: scan
// is a report, not a gate.
func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	rootsFlag := multiFlag{}
	fs.Var(&rootsFlag, "roots", "narrow the scan to these configured roots (never widens)")
	minGB := fs.Float64("min-gb", 0, "listing floor in GB (report-only; totals count everything)")
	noGH := fs.Bool("no-gh", false, "skip the open-PR fact (weakens verdicts to MANUAL, never strengthens)")
	noJJ := fs.Bool("no-jj", false, "skip jj facts (weakens verdicts, never strengthens)")
	asJSON := fs.Bool("json", false, "emit the machine schema")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	stateDir, err := config.StateDir()
	if err != nil {
		fmt.Fprintf(stderr, "reap scan: %v\n", err)
		return ExitState
	}
	cfg, err := config.Load(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap scan: %v\n", err)
		return ExitState
	}
	gitBudget, jjBudget, ghBudget, fetchBudget, err := cfg.Thresholds.Budgets()
	if err != nil {
		fmt.Fprintf(stderr, "reap scan: %v\n", err)
		return ExitState
	}

	roots, err := narrowRoots(config.ExpandRoots(cfg.Roots), rootsFlag)
	if err != nil {
		fmt.Fprintf(stderr, "reap scan: %v\n", err)
		return ExitUsage
	}

	now := time.Now()

	// One gh call for the whole run (two-phase inside, bounded), before any
	// verdict: an unavailable set routes every dependent dir to
	// gh-unavailable, never to "no open PRs".
	var prHeads *ghx.PRHeads
	if !*noGH && cfg.GH {
		h := ghx.Client{Budget: ghBudget}.OpenPRHeads()
		prHeads = &h
	}
	useJJ := !*noJJ && cfg.JJ && jjx.Available()
	useGit := gitx.Available()

	// Unreadable roots are named, not silently skipped: a configured root
	// that cannot be listed yields a marker DirInfo, and hiding it would let
	// a denied-ACL root read as "scanned, found nothing".
	infos := walk.Roots(roots, now, 8)
	var unreadableRoots []string
	var candidates []walk.DirInfo
	for _, info := range infos {
		if info.Root == info.Path {
			unreadableRoots = append(unreadableRoots, info.Path)
			continue
		}
		candidates = append(candidates, info)
	}

	// Corrupt protective state must fail the scan rather than silently
	// vanish: a truncated holds.json (or a bad protect glob) un-protecting
	// dirs is the worst failure direction reap has.
	holds, err := loadHolds(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap scan: %v\n", err)
		return ExitState
	}
	protectedExpanded := config.ExpandRoots(cfg.Protect)
	if _, err := config.MatchProtect(".", protectedExpanded); err != nil {
		fmt.Fprintf(stderr, "reap scan: %v\n", err)
		return ExitState
	}
	remoteStale := time.Duration(cfg.Thresholds.RemoteStaleHours) * time.Hour

	// Facts phase: bounded pool, 4 workers (cold git status on big clones is
	// the real cost; 4 keeps the machine responsive while walking).
	var (
		mu      sync.Mutex
		entries []report.Entry
		wg      sync.WaitGroup
		jobs    = make(chan walk.DirInfo)
	)
	var done int
	total := len(candidates)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for info := range jobs {
				e := buildEntry(info, now, cfg, holds, useGit, useJJ, prHeads,
					gitBudget, jjBudget, fetchBudget, remoteStale, protectedExpanded)
				mu.Lock()
				entries = append(entries, e)
				done++
				// Progress after a few seconds of work, on stderr, never in
				// --json mode: a >60s silent scan reads as a hang.
				if !*asJSON && done%16 == 0 {
					fmt.Fprintf(stderr, "reap scan: %d/%d dirs\n", done, total)
				}
				mu.Unlock()
			}
		}()
	}
	for _, info := range candidates {
		jobs <- info
	}
	close(jobs)
	wg.Wait()

	// Lineage groups via the tested API (the inline copy had drifted).
	var lgs []verdict.LineageEntry
	for _, e := range entries {
		if e.Origin != "" && e.Unpushed > 100 {
			lgs = append(lgs, verdict.LineageEntry{Path: e.Path, Origin: e.Origin, Unpushed: e.Unpushed})
		}
	}
	groupOf := map[string]string{}
	for _, g := range verdict.LineageGroups(lgs, 100) {
		detail := fmt.Sprintf("shared lineage: %d dirs report %d unpushed (resolve at branch level)", len(g.Members), g.Count)
		for _, p := range g.Members {
			groupOf[p] = detail
		}
	}
	for i := range entries {
		if g, ok := groupOf[entries[i].Path]; ok {
			entries[i].LineageGroup = strPtr(g)
			if entries[i].ReasonCode == "unpushed-commits" {
				entries[i].Reason = entries[i].Reason + " [" + g + "]"
			}
		}
	}

	var rootSummaries []report.RootSummary
	for _, root := range roots {
		var n int
		var bytes int64
		for _, e := range entries {
			if e.Zone == root {
				n++
				bytes += e.SizeBytes
			}
		}
		rootSummaries = append(rootSummaries, report.RootSummary{Path: root, Dirs: n, SizeGB: float64(int(float64(bytes)/(1<<30)*10)) / 10})
	}
	rep := report.Build(now, rootSummaries, entries, *minGB)
	rep.UnreadableRoots = unreadableRoots
	for range unreadableRoots {
		rep.Totals.Errors++
	}
	if *asJSON {
		if err := rep.JSON(stdout); err != nil {
			fmt.Fprintf(stderr, "reap scan: %v\n", err)
			return ExitState
		}
		return ExitOK
	}
	for _, u := range unreadableRoots {
		fmt.Fprintf(stderr, "reap scan: unreadable root skipped: %s\n", u)
	}
	rep.Table(stdout)
	return ExitOK
}

func buildEntry(info walk.DirInfo, now time.Time, cfg config.Config, holds map[string]bool,
	useGit, useJJ bool, prHeads *ghx.PRHeads,
	gitBudget, jjBudget, fetchBudget, remoteStale time.Duration, protectExpanded []string) report.Entry {

	e := report.Entry{
		Path:         info.Path,
		Zone:         info.Root,
		SizeBytes:    info.Bytes,
		SizePartial:  info.Partial,
		LastActivity: info.MaxMtime,
		ClampedFiles: info.Clamped,
		AgeDays:      int(now.Sub(info.MaxMtime).Hours() / 24),
	}

	// Reparse candidates are NEVER read through: no classify, no facts, no
	// activity — the KEEP row decides, on the link's own nature.
	if info.IsReparse {
		in := verdict.Input{Path: info.Path, Kind: classify.KindScratch, IsReparse: true,
			Thresholds: cfg.Thresholds, Now: now}
		v := verdict.Decide(in)
		e.Kind = "reparse"
		e.Verdict = v.Verdict
		e.ReasonCode = v.Code
		e.Reason = v.Reason
		e.Hint = v.Hint
		return e
	}

	classInfo := classify.Dir(info.Path)
	e.Kind = string(classInfo.Kind)

	gr := gitx.Runner{GitBudget: gitBudget, FetchBudget: fetchBudget}
	jr := jjx.Runner{Budget: jjBudget}

	in := verdict.Input{
		Path:         info.Path,
		Kind:         classInfo.Kind,
		SizeBytes:    info.Bytes,
		SizePartial:  info.Partial,
		LastActivity: info.MaxMtime,
		NestedVCS:    info.NestedVCS,
		Thresholds:   cfg.Thresholds,
		Now:          now,
	}

	// git facts where a git backend is REACHABLE for the kind. Pure
	// split-layout jj repos have no .git: running git there yields a bogus
	// state-unreadable that shadows the jj rows. Orphaned kinds with a live
	// parent (broken-branch flavor) still attempt facts, so the carve-out
	// can name real counts; parent-gone orphans leave them nil.
	gitReachable := false
	switch classInfo.Kind {
	case classify.KindGitRepo, classify.KindGitWorktree, classify.KindJJRepo, classify.KindJJWorkspace:
		gitReachable = true
	case classify.KindGitWorktreeOrphaned:
		gitReachable = classInfo.ParentRepo != ""
	}
	if useGit && gitReachable {
		f := gr.Facts(info.Path, now, remoteStale)
		in.Git = &f
		e.Branch = f.Branch
		e.Dirty = f.Dirty
		e.Untracked = f.Untracked
		e.Ignored = f.Ignored
		e.Stashes = f.Stashes
		e.Unpushed = f.Unpushed
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

	// jj facts for jj kinds; unavailable jj marks the downgrade (Decide
	// routes it to facts-unavailable, never vacuously clean).
	jjReachable := classInfo.Kind == classify.KindJJRepo || classInfo.Kind == classify.KindJJWorkspace
	if useJJ && jjReachable {
		f := jr.Facts(info.Path, now, remoteStale)
		in.JJ = &f
		if f.Unavailable {
			e.DowngradedBy = strPtr("jj")
		}
	} else if jjReachable {
		e.DowngradedBy = strPtr("jj")
	}

	in.PRHeads = prHeads
	if prHeads != nil && prHeads.Unavailable {
		e.DowngradedBy = strPtr("gh")
	}
	in.Held = anyHoldUnder(holds, info.Path)
	protected, _ := config.MatchProtect(info.Path, protectExpanded)
	in.Protected = protected

	v := verdict.Decide(in)
	e.Verdict = v.Verdict
	e.ReasonCode = v.Code
	e.Reason = v.Reason
	e.Hint = v.Hint
	e.Held = in.Held
	e.BlockedClassFact = v.BlockedClassFact
	e.OrphanedCarveOut = v.OrphanedCarveOut
	e.OpenPR = v.OpenPRSlug != ""
	// The orphaned detail: counts when they are knowable, honestly
	// "unknowable" when the parent is gone (the M2 hardened confirm needs
	// exactly this distinction).
	if v.OrphanedCarveOut && v.BlockedClassFact != "" {
		e.Reason = e.Reason + fmt.Sprintf(" (also: %s)", v.BlockedClassFact)
	}
	return e
}

// narrowRoots intersects requested roots with configured ones: --roots only
// ever narrows, and an unconfigured path is a usage error naming it, so a
// typo cannot silently scan the whole disk instead. UNC roots are refused
// outright: network volumes have different lock/rename semantics and their
// placeholder trees are exactly what the spec refuses to walk.
func narrowRoots(configured []string, requested []string) ([]string, error) {
	if len(requested) == 0 {
		for _, c := range configured {
			if strings.HasPrefix(filepath.VolumeName(c), `\\`) {
				return nil, fmt.Errorf("root %s is a network path; scan refuses UNC roots", c)
			}
		}
		return configured, nil
	}
	var out []string
	for _, r := range requested {
		if strings.HasPrefix(filepath.VolumeName(r), `\\`) {
			return nil, fmt.Errorf("root %s is a network path; scan refuses UNC roots", r)
		}
		rc := config.Canonical(r)
		matched := false
		for _, c := range configured {
			if rc == config.Canonical(c) {
				out = append(out, c)
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("--roots %s is not a configured root (scan refuses to widen)", r)
		}
	}
	return out, nil
}

// strPtr is the *string helper for the nullable schema fields.
func strPtr(s string) *string { return &s }

// holds.json is written by reap hold (M3); scan reads it, and a CORRUPT
// file is a hard error: silently dropping every hold is the worst failure
// direction (a pinned dir verdicting SAFE).
type holdsFile map[string]holdEntry

type holdEntry struct {
	Expires time.Time `json:"expires"`
}

func loadHolds(stateDir string) (map[string]bool, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "holds.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read holds.json: %w", err)
	}
	var hf holdsFile
	if err := json.Unmarshal(raw, &hf); err != nil {
		return nil, fmt.Errorf("holds.json is corrupt (refusing to silently drop holds): %w", err)
	}
	now := time.Now()
	out := map[string]bool{}
	for p, h := range hf {
		if h.Expires.IsZero() || h.Expires.After(now) {
			out[config.Canonical(p)] = true
		}
	}
	return out, nil
}

func anyHoldUnder(holds map[string]bool, path string) bool {
	if len(holds) == 0 {
		return false
	}
	pc := config.Canonical(path)
	// A hold on the path itself or any ancestor: walk up component by
	// component (bounded by canonical form).
	parts := splitPath(pc)
	for i := len(parts); i >= 1; i-- {
		if holds[joinPath(parts[:i])] {
			return true
		}
	}
	return false
}

func splitPath(p string) []string {
	var out []string
	for {
		i := lastIndexSep(p)
		if i <= 0 {
			if p != "" {
				out = append([]string{p}, out...)
			}
			return out
		}
		out = append([]string{p[i+1:]}, out...)
		p = p[:i]
	}
}

func lastIndexSep(p string) int {
	max := -1
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' || p[i] == '/' {
			max = i
		}
	}
	return max
}

func joinPath(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += string(os.PathSeparator) + p
	}
	return out
}
