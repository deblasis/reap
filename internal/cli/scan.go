package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	cache, _ := walk.LoadCache(stateDir)
	if cache == nil {
		cache = &walk.Cache{} // unusable cache degrades to full walks, never to failure
	}

	// One gh call for the whole run (two-phase inside), before any verdict:
	// an unavailable set routes every dependent dir to gh-unavailable, never
	// to "no open PRs".
	var prHeads *ghx.PRHeads
	if !*noGH && cfg.GH {
		h := ghx.Client{Budget: ghBudget}.OpenPRHeads()
		prHeads = &h
	}
	useJJ := !*noJJ && cfg.JJ && jjx.Available()
	useGit := gitx.Available()

	infos := walk.Roots(roots, now, 8)
	holds := loadHolds(stateDir)
	remoteStale := time.Duration(cfg.Thresholds.RemoteStaleHours) * time.Hour

	// Facts phase: bounded pool, 4 workers (cold git status on big clones is
	// the real cost; 4 keeps the machine responsive while walking).
	var (
		mu      sync.Mutex
		entries []report.Entry
		wg      sync.WaitGroup
		jobs    = make(chan walk.DirInfo)
	)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for info := range jobs {
				e := buildEntry(info, now, cfg, holds, useGit, useJJ, prHeads,
					gitBudget, jjBudget, fetchBudget, remoteStale, stateDir)
				mu.Lock()
				entries = append(entries, e)
				mu.Unlock()
				cache.Record(info.Path, info, now)
			}
		}()
	}
	for _, info := range infos {
		if info.Root == info.Path {
			continue // unreadable-root marker; counted via its children absence
		}
		jobs <- info
	}
	close(jobs)
	wg.Wait()
	_ = cache.Save()

	// Lineage groups: same origin, identical huge unpushed count.
	type lg struct {
		path     string
		origin   string
		unpushed int
	}
	var lgs []lg
	for _, e := range entries {
		if e.Origin != "" && e.Unpushed > 100 {
			lgs = append(lgs, lg{e.Path, e.Origin, e.Unpushed})
		}
	}
	groupOf := map[string]string{}
	buckets := map[string][]lg{}
	for _, x := range lgs {
		k := fmt.Sprintf("%s\x00%d", x.origin, x.unpushed)
		buckets[k] = append(buckets[k], x)
	}
	for k, xs := range buckets {
		if len(xs) < 2 {
			continue
		}
		for _, x := range xs {
			groupOf[x.path] = fmt.Sprintf("shared lineage: %d dirs report %d unpushed (resolve at branch level)", len(xs), x.unpushed)
		}
		_ = k
	}
	for i := range entries {
		if g, ok := groupOf[entries[i].Path]; ok {
			entries[i].LineageGroup = g
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
	if *asJSON {
		if err := rep.JSON(stdout); err != nil {
			fmt.Fprintf(stderr, "reap scan: %v\n", err)
			return ExitState
		}
		return ExitOK
	}
	rep.Table(stdout)
	return ExitOK
}

func buildEntry(info walk.DirInfo, now time.Time, cfg config.Config, holds map[string]bool,
	useGit, useJJ bool, prHeads *ghx.PRHeads,
	gitBudget, jjBudget, fetchBudget, remoteStale time.Duration, stateDir string) report.Entry {

	e := report.Entry{
		Path:         info.Path,
		Zone:         info.Root,
		SizeBytes:    info.Bytes,
		SizePartial:  info.Partial,
		LastActivity: info.MaxMtime,
		ClampedFiles: info.Clamped,
		AgeDays:      int(now.Sub(info.MaxMtime).Hours() / 24),
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
		IsReparse:    false, // reparse candidates are surfaced, not walked, by Roots
		Thresholds:   cfg.Thresholds,
		Now:          now,
	}

	// git facts for every git-bearing kind; a missing git binary is an
	// unavailable fact, not a skipped one.
	if useGit && classInfo.Kind != classify.KindScratch && classInfo.Kind != classify.KindUnknown &&
		classInfo.Kind != classify.KindJJWorkspaceOrphaned && classInfo.Kind != classify.KindGitWorktreeOrphaned {
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
			e.DowngradedBy = "git"
		}
		for name, url := range gr.Remotes(info.Path) {
			if slug := ghx.SlugFromURL(url); slug != "" {
				in.RemoteSlugs = append(in.RemoteSlugs, slug)
				if name == "origin" {
					e.Origin = slug
				}
			}
		}
	}
	if useJJ && (classInfo.Kind == classify.KindJJRepo || classInfo.Kind == classify.KindJJWorkspace) {
		f := jr.Facts(info.Path, now, remoteStale)
		in.JJ = &f
		if f.Unavailable {
			e.DowngradedBy = "jj"
		}
	}
	in.PRHeads = prHeads
	if prHeads != nil && prHeads.Unavailable {
		e.DowngradedBy = "gh"
	}
	in.Held = anyHoldUnder(holds, info.Path)
	protected, _ := config.MatchProtect(info.Path, config.ExpandRoots(cfg.Protect))
	in.Protected = protected

	v := verdict.Decide(in)
	e.Verdict = v.Verdict
	e.ReasonCode = v.Code
	e.Reason = v.Reason
	e.Hint = v.Hint
	e.Held = in.Held
	e.BlockedClassFact = v.BlockedClassFact
	e.OrphanedCarveOut = v.OrphanedCarveOut
	if in.PRHeads != nil && !in.PRHeads.Unavailable {
		if slug, branch := inOpenPR(in); slug != "" {
			e.OpenPR = true
			_ = branch
		}
	}
	return e
}

// inOpenPR mirrors verdict's join for the entry's OpenPR flag (kept in sync
// by the integration tests; verdict's own method stays unexported).
func inOpenPR(in verdict.Input) (string, string) {
	for _, s := range in.RemoteSlugs {
		if in.PRHeads.Holds(s, in.Git.Branch) {
			return s, in.Git.Branch
		}
	}
	return "", ""
}

// narrowRoots intersects requested roots with configured ones: --roots only
// ever narrows, and an unconfigured path is a usage error naming it, so a
// typo cannot silently scan the whole disk instead.
func narrowRoots(configured []string, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return configured, nil
	}
	var out []string
	for _, r := range requested {
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

// holds.json is written by reap hold (M3); scan reads it leniently.
type holdsFile map[string]holdEntry

type holdEntry struct {
	Expires time.Time `json:"expires"`
}

func loadHolds(stateDir string) map[string]bool {
	raw, err := os.ReadFile(filepath.Join(stateDir, "holds.json"))
	if err != nil {
		return nil
	}
	var hf holdsFile
	if err := json.Unmarshal(raw, &hf); err != nil {
		return nil
	}
	now := time.Now()
	out := map[string]bool{}
	for p, h := range hf {
		if h.Expires.IsZero() || h.Expires.After(now) {
			out[config.Canonical(p)] = true
		}
	}
	return out
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
