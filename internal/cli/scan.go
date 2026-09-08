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
	"github.com/deblasis/reap/internal/dedupe"
	"github.com/deblasis/reap/internal/ghx"
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/incodalog"
	"github.com/deblasis/reap/internal/jjx"
	"github.com/deblasis/reap/internal/quarantine"
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

	// incoda attribution (M4): the lane.log digest + live-ticket probe,
	// computed ONCE per scan. The live set carries BOTH triggers (spec
	// L320-322/L342): a held ticket backing an open record (incl pure
	// tickets the best-effort log never recorded) AND open events within
	// the active-hours window. The digest records ride alongside for the
	// 'last:' row enrichment.
	incodaLive, incodaRecords := incodaSnapshot(time.Duration(cfg.Thresholds.ActiveHours) * time.Hour)

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
	holds, expiredHolds, err := loadHoldsWithExpired(stateDir)
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
				e := buildEntry(info, now, cfg, holds, expiredHolds, useGit, useJJ, prHeads,
					gitBudget, jjBudget, fetchBudget, remoteStale, protectedExpanded, incodaLive, incodaRecords)
				mu.Lock()
				entries = append(entries, e)
				done++
				// Progress is TIME-gated (the spec: "after a few seconds"),
				// on stderr, never in --json mode: a fast scan stays silent
				// and a >60s silent scan reads as a hang.
				if !*asJSON && done%16 == 0 && time.Since(now) > 3*time.Second {
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
	// reclaimableGB: the hardlink pass over the SAFE set (spec L511-514)  - 
	// hardlinked content shared within the deletable set reclaims once.
	// Null + caveat stands when the pass skips (file bound or unsupported
	// filesystem). JSON-only: text never renders the field, and the walk
	// is 50k file opens otherwise spent for nothing.
	if *asJSON {
		var safePaths []string
		for _, e := range entries {
			if e.ReasonCode == "clean-pushed" || e.ReasonCode == "scratch-idle" {
				safePaths = append(safePaths, e.Path)
			}
		}
		if len(safePaths) > 0 {
			c := dedupe.NewCounter(50000)
			if dedupe.IndexesAvailable(safePaths[0]) {
				for _, p := range safePaths {
					c.Add(p)
				}
				if !c.Over() && c.Expected > 0 {
					gb := float64(c.Expected) / (1 << 30)
					rep.Totals.ReclaimableGB = &gb
				}
			}
		}
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
	// The quarantine footer (spec presentation): sessions hold recoverable
	// bytes and expire by retention, so every scan that shows deletable
	// bytes also shows what is being kept back and how to release it.
	if sessions := quarantine.List(stateDirOfScan()); len(sessions) > 0 {
		var total int64
		oldest := 0
		for _, s := range sessions {
			total += quarantine.Bytes(s.Dir)
			if fi, err := os.Stat(s.Dir); err == nil {
				if d := int(time.Since(fi.ModTime()).Hours() / 24); d > oldest {
					oldest = d
				}
			}
		}
		fmt.Fprintf(stdout, "quarantine holds %d MB, oldest %dd (reap quarantine prune)\n", total>>20, oldest)
	}
	return ExitOK
}

// stateDirOfScan resolves the state dir for the scan-side quarantine
// footer (the command already resolved it once for holds; this stays a
// cheap re-read).
func stateDirOfScan() string {
	d, err := config.StateDir()
	if err != nil {
		return ""
	}
	return d
}

// anyIncodaUnder reports whether any live-incoda dir sits AT or UNDER
// path (spec L342: 'live incoda ticket at/under dir' - the descendant
// half is the deletion-relevant one: a parent containing a live session's
// workdir must not verdict SAFE). The map is small; iterate its keys with
// a component-boundary prefix check. (anyHoldUnder's ancestor walk is the
// RIGHT direction for holds and the WRONG one here - holds pin from
// above, work happens below.)
func anyIncodaUnder(live map[string]bool, path string) bool {
	if len(live) == 0 {
		return false
	}
	// The unknown-live sentinel (an existing-but-unlistable queues dir):
	// every candidate is live-unknown, never silently unmarked.
	if live[""] {
		return true
	}
	pc := config.Canonical(path)
	for k := range live {
		if k == pc || strings.HasPrefix(k, pc+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// defaultConfirmReprobeLive is confirmReprobeLive's real implementation.
func defaultConfirmReprobeLive(activeHours time.Duration) map[string]bool {
	live, _ := incodaSnapshot(activeHours)
	return live
}

// confirmReprobeLive is the under-lock confirm-window re-probe source.
// A seam, not indirection: a ticket created BEFORE the run is caught at
// scan time (the row verdicts ACTIVE/incoda-live and never plans), so the
// mid-window abort cannot be hit deterministically with a pre-created
// ticket - tests inject the held set here (the auditlog.FreeBytes pattern).
var confirmReprobeLive = defaultConfirmReprobeLive

// perPathTicketHit is the per-path pre-deletion re-sweep seam (same
// pattern): the window it covers is between the confirm-window probe and
// each path's deletion, unreachable with fixtures alone. The CAUSE rides
// along: an unknown-rail trip must not be worded as 'a ticket sits here'
// (the remedies differ - fix-the-rail vs wait-for-the-job).
var perPathTicketHit = incodalog.LiveTicketHit

// unknownRailNote is the honest copy for an unknown-rail trip (the R5
// reliability finding: the refusal named a mechanism that did not happen).
const unknownRailNote = "incoda rail UNKNOWN-LIVE (enumeration incomplete; run reap doctor for the named failures)"

// incodaSnapshot reads incoda state ONCE per invocation: one ticket sweep
// plus ONE lane.log parse feed BOTH the live map and the enrichment
// records (the R4 panel measured ~1.8s per parse on a 923KB log - two
// parses per scan and three per apply, with lane.log append-only and
// unrotated upstream, was unbounded read amplification). The live set
// carries BOTH triggers (spec L320-322/L342): a held ticket backing an
// open record (incl pure tickets the best-effort log never recorded) AND
// open events within the active-hours window. A "" entry is the
// unknown-live sentinel (any enumeration failure in the sweep): the
// conservative direction, not a silent-empty rail.
func incodaSnapshot(activeHours time.Duration) (live map[string]bool, records map[string]*incodalog.Record) {
	live = map[string]bool{}
	// ONE sweep: every held ticket's dir (the authoritative signal -
	// Queue.Logf swallows write failures, so the log may have missed it).
	ticketDirs := incodalog.LiveTicketDirs()
	ticketSet := map[string]bool{}
	for _, d := range ticketDirs {
		if d == "" {
			live[""] = true
			continue
		}
		d = config.Canonical(d)
		ticketSet[d] = true
		live[d] = true
	}
	// Log triggers, joined against the ONE sweep (membership, not probing).
	records, _ = incodalog.Digest(incodalog.ReadAll())
	cutoff := time.Now().Add(-activeHours)
	for _, r := range records {
		if r.Open && ticketSet[config.Canonical(r.Dir)] {
			live[config.Canonical(r.Dir)] = true
		}
		if r.Open && !r.LastEvent.Before(cutoff) {
			live[config.Canonical(r.Dir)] = true
		}
	}
	return live, records
}

// LastIncoda is the per-entry attribution enrichment (spec L501): the
// digest's record for the dir, rendered as the 'last:' row detail.
type LastIncoda = report.Incoda

// lastIncodaFor shapes a digest record into the entry enrichment (nil when
// the dir has no record - the renderer's explicit 'no incoda record').
func lastIncodaFor(r *incodalog.Record, now time.Time) *LastIncoda {
	if r == nil {
		return nil
	}
	return &LastIncoda{Ago: humanAgo(now.Sub(r.LastEvent)), Owner: r.Owner, Reason: r.Reason}
}

// humanAgo renders the mock's compact units ('2h', '3d', '45m', '30s') -
// Go's Duration.String spells '72h0m0s' where every surface here says '3d'.
func humanAgo(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}

func buildEntry(info walk.DirInfo, now time.Time, cfg config.Config, holds map[string]bool, expiredHolds map[string]time.Time,
	useGit, useJJ bool, prHeads *ghx.PRHeads,
	gitBudget, jjBudget, fetchBudget, remoteStale time.Duration, protectExpanded []string,
	incodaLive map[string]bool, incodaRecords map[string]*incodalog.Record) report.Entry {

	e := report.Entry{
		Path:         info.Path,
		Zone:         info.Root,
		SizeBytes:    info.Bytes,
		SizePartial:  info.Partial,
		LastActivity: &info.MaxMtime,
		ClampedFiles: info.Clamped,
		AgeDays:      int(now.Sub(info.MaxMtime).Hours() / 24),
	}

	// Reparse candidates are NEVER read through: no classify, no facts, no
	// activity  -  the KEEP row decides, on the link's own nature. The
	// never-walked fields stay zero (no 0001-01-01 sentinels, no 106751-day
	// ages): "kind":"reparse" is the documented marker.
	if info.IsReparse {
		in := verdict.Input{Path: info.Path, Kind: classify.KindScratch, IsReparse: true,
			Thresholds: cfg.Thresholds, Now: now}
		v := verdict.Decide(in)
		e.Kind = "reparse"
		e.LastActivity = nil
		e.AgeDays = 0
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
		GitBackend:   classInfo.GitBackend,
		Thresholds:   cfg.Thresholds,
		Now:          now,
	}

	// git facts only where classify found a git BACKEND (a root .git or a
	// linked .git file)  -  or an orphaned worktree whose parent metadata is
	// intact (the broken-branch flavor), so the carve-out can name real
	// counts. Split-layout jj repos decide on jj facts alone.
	gitReachable := classInfo.GitBackend ||
		(classInfo.Kind == classify.KindGitWorktreeOrphaned && classInfo.ParentRepo != "")
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
		// The re-route is WORKSPACE-shaped only (round 10): a root jj repo
		// emitting the phrase would misroute; the parent must have resolved
		// alive (classify said workspace, not orphaned).
		if f.Deregistered && classInfo.Kind == classify.KindJJWorkspace {
			// The forget-then-rm crash shape (parent alive, this dir out of
			// its registry): route to the carve-out, NOT the no-deletion-path
			// ignorance class. KEEP rails first (round 10: the early return
			// previously skipped Held/Protected, displaying an override hint
			// on a HELD dir); the kind is stamped for the row it now is.
			in.Held = anyHoldUnder(holds, info.Path)
			in.Protected, _ = config.MatchProtect(info.Path, protectExpanded)
			in.PRHeads = prHeads
			classInfo = classify.Info{Kind: classify.KindJJWorkspaceOrphaned}
			in.Kind = classInfo.Kind
			in.GitBackend = false
			e.Kind = string(classInfo.Kind)
			v := verdict.Decide(in)
			v.Flavor = verdict.FlavorDeregistered
			e.Verdict = v.Verdict
			e.ReasonCode = v.Code
			// The reason must not say "parent gone" when the parent is
			// alive: this shape is DEREGISTERED (the forget-then-rm crash
			// window), not parent-less. Every other code (KEEP rails,
			// ACTIVE) keeps its own story - including a non-empty reason
			// (round 12: the if-only form left held rows with a BLANK one).
			if v.Code == "orphaned-workspace" {
				e.Reason = "deregistered workspace (parent alive, this dir is out of its registry)"
				v.Hint = "deregistered workspace (parent alive, this dir is out of its registry); reap apply --override-manual asks a TTY-only hardened confirm"
			} else {
				e.Reason = v.Reason
			}
			if v.BlockedClassFact != "" {
				e.Reason += fmt.Sprintf(" (also: %s)", v.BlockedClassFact)
			}
			e.Hint = v.Hint
			e.Held = in.Held
			e.OrphanedCarveOut = v.OrphanedCarveOut
			e.BlockedClassFact = v.BlockedClassFact
			return e
		}
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
	// incoda attribution (M4): a live ticket at/under the dir is the
	// ACTIVE incoda-live rail (enrichment; the empty map weakens nothing).
	in.IncodaLive = anyIncodaUnder(incodaLive, info.Path)
	// The 'last:' enrichment: this exact dir's digest record (the records
	// map is computed once per scan, passed in).
	e.LastIncoda = lastIncodaFor(incodaRecords[config.Canonical(info.Path)], now)
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
	// Expiry-at-consequence, scan half: a pin that lapsed within 7 days
	// marks the row so the KEEP->other flip is visible on the main screen
	// (plan renders its own distinct section from the same side map).
	if exp, ok := expiredHolds[config.Canonical(info.Path)]; ok {
		e.Reason = e.Reason + fmt.Sprintf(" [hold expired %s (%dd ago)]", exp.Format("2006-01-02"), int(now.Sub(exp).Hours()/24))
	}
	e.OpenPR = v.OpenPRSlug != ""
	// The shadowed detail (round 14: the gate was carve-out-only, leaving
	// held/protected KEEP rows bare against the spec's UNQUALIFIED 'rows
	// with shadowed facts carry the (also: ...) detail'). A BLOCKED row
	// does not suffix itself (its own reason IS the fact).
	if v.BlockedClassFact != "" && v.Verdict != verdict.Blocked {
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
	active, _, err := loadHoldsWithExpired(stateDir)
	return active, err
}

// loadHoldsWithExpired also returns recently-EXPIRED holds (within 7 days)
// keyed by canonical path with their expiry time: the spec's
// expiry-at-consequence map. A pinned dir's verdict flips KEEP->other the
// moment the pin lapses; without this map that flip is silent.
func loadHoldsWithExpired(stateDir string) (map[string]bool, map[string]time.Time, error) {
	raw, err := os.ReadFile(filepath.Join(stateDir, "holds.json"))
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read holds.json: %w", err)
	}
	var hf holdsFile
	if err := json.Unmarshal(raw, &hf); err != nil {
		return nil, nil, fmt.Errorf("holds.json is corrupt (refusing to silently drop holds): %w", err)
	}
	now := time.Now()
	active := map[string]bool{}
	expired := map[string]time.Time{}
	for p, h := range hf {
		cp := config.Canonical(p)
		if h.Expires.IsZero() || h.Expires.After(now) {
			active[cp] = true
			continue
		}
		if now.Sub(h.Expires) < 7*24*time.Hour {
			expired[cp] = h.Expires
		}
	}
	return active, expired, nil
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
