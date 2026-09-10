package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/ghx"
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/incodalog"
	"github.com/deblasis/reap/internal/jjx"
	"github.com/deblasis/reap/internal/lockfile"
	"github.com/deblasis/reap/internal/quarantine"
)

// cmdDoctor implements `reap doctor`: the state-of-the-world readout.
func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	stateDir, err := config.StateDir()
	if err != nil {
		fmt.Fprintf(stderr, "reap doctor: %v\n", err)
		return ExitState
	}
	cfg, err := config.Load(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap doctor: %v\n", err)
		return ExitState
	}

	fmt.Fprintf(stdout, "state dir: %s\n", stateDir)
	fmt.Fprintf(stdout, "config: %s (roots below as expanded; elevated contexts resolve %%TEMP%% elsewhere)\n", config.ConfigPath(stateDir))
	for _, r := range config.ExpandRoots(cfg.Roots) {
		marker := ""
		if fi, err := os.Stat(r); err != nil {
			marker = "  (unreadable)"
		} else if !fi.IsDir() {
			marker = "  (not a directory)"
		}
		fmt.Fprintf(stdout, "  root: %s%s\n", r, marker)
	}

	// Lock state.
	lockPath := filepath.Join(stateDir, "apply.lock")
	if l, err := lockfile.Open(lockPath); err == nil {
		free, ferr := l.TryLock()
		l.Close()
		if ferr == nil && !free {
			holder := "(unknown holder)"
			if raw, rerr := os.ReadFile(lockPath); rerr == nil && len(raw) > 0 {
				holder = strings.TrimSpace(string(raw))
			}
			fmt.Fprintf(stdout, "apply.lock: HELD by %s\n", holder)
		} else if ferr == nil {
			fmt.Fprintf(stdout, "apply.lock: free\n")
		}
	}

	// Quarantine readout, with per-bundle revalidation states (one ls-remote
	// per DELTA bundle: verified-ok / at-risk / unverified, never conflated).
	gr := gitx.Runner{GitBudget: 15 * time.Second, FetchBudget: 15 * time.Second}
	qTotal, qOldest := quarantineStats(stateDir)
	fmt.Fprintf(stdout, "quarantine: %d MB across sessions, oldest %dd\n", qTotal>>20, qOldest)
	states := map[string]int{"verified-ok": 0, "at-risk": 0, "unverified": 0}
	for _, s := range quarantine.List(stateDir) {
		if s.Manifest == nil {
			states["unverified"]++
			fmt.Fprintf(stdout, "  bundle %s: unverified (no manifest; verify with git bundle verify before trusting)\n", filepath.Base(s.Dir))
			continue
		}
		st := string(quarantine.Revalidate(gr, s.Manifest, s.Dir))
		states[st]++
		fmt.Fprintf(stdout, "  bundle %s: %s\n", filepath.Base(s.Dir), st)
	}
	fmt.Fprintf(stdout, "quarantine revalidation: %d verified-ok, %d at-risk, %d unverified\n",
		states["verified-ok"], states["at-risk"], states["unverified"])

	// Ledger: size, rotation state, covered span, free-space deltas since
	// the last apply (from audit envelopes), and downgraded-dirs counts.
	ledger := ledgerStats(stateDir)
	rot := "active only"
	if ledger.rotations > 0 {
		rot = fmt.Sprintf("active + %d rotation(s)", ledger.rotations)
	}
	fmt.Fprintf(stdout, "reap.log: %d KB, %d line(s), %s, spans %s\n", ledger.bytes>>10, ledger.lines, rot, ledger.span)
	if ledger.freeDelta != nil {
		d := *ledger.freeDelta
		sign := "+"
		if d < 0 {
			sign = ""
		}
		fmt.Fprintf(stdout, "free-space delta since last apply: %s%d MB (from envelopes)\n", sign, d>>20)
	}
	fmt.Fprintf(stdout, "dirs downgraded by gh/jj unavailability (last logged run): %d\n", ledger.downgraded)

	// Tool health.
	ghInstalled, ghAuthed := ghx.Client{Budget: 15 * time.Second}.AuthStatus()
	if ghInstalled {
		if ghAuthed {
			fmt.Fprintf(stdout, "gh: installed and authenticated\n")
		} else {
			fmt.Fprintf(stdout, "gh: installed but NOT authenticated (SAFE silently collapses to near zero; run gh auth login)\n")
		}
	} else {
		fmt.Fprintf(stdout, "gh: not on PATH (open-PR fact unavailable)\n")
	}
	if jjx.Available() {
		fmt.Fprintf(stdout, "jj: installed\n")
	} else {
		fmt.Fprintf(stdout, "jj: not on PATH (jj facts degrade to facts-unavailable)\n")
	}

	// incoda state (M4): the CANDIDATE-DIR attribution share (spec L194:
	// 'the share of candidate dirs with real dir= attribution' - root
	// children joined against the digest, not the raw event share) and the
	// state dir's reachability.
	incEvents := incodalog.ReadAll()
	if len(incEvents) == 0 {
		fmt.Fprintf(stdout, "incoda: no lane.log found (attribution off; %s)\n", incodalog.StateDir())
	} else {
		records, _ := incodalog.Digest(incEvents)
		candidates := map[string]bool{}
		for _, r := range config.ExpandRoots(cfg.Roots) {
			entries, derr := os.ReadDir(r)
			if derr != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() {
					candidates[config.Canonical(filepath.Join(r, e.Name()))] = true
				}
			}
		}
		attributed := 0
		for c := range candidates {
			if _, ok := records[c]; ok {
				attributed++
			}
		}
		fmt.Fprintf(stdout, "incoda: state dir found; dir= attribution %d/%d candidate dir(s); old-format events are COUNTED, not attributed, until the dir= PR ships\n",
			attributed, len(candidates))
	}
	// The live-ticket rail's enumeration honesty (round 5): any failure
	// level makes every candidate read live-or-unknown; doctor NAMES the
	// failures so the operator can fix the ACL / the torn ticket instead of
	// wondering why everything rows ACTIVE.
	if h := incodalog.ProbeRail(); h.Unknown {
		fmt.Fprintf(stdout, "incoda rail: UNKNOWN-LIVE (enumeration incomplete: %d unreadable queue dir(s), %d held ticket(s) without a readable dir); every dir reads live-or-unknown until these resolve\n",
			len(h.UnreadableQueues), len(h.UnattributableLive))
		for _, q := range h.UnreadableQueues {
			fmt.Fprintf(stdout, "  unreadable queue dir: %s\n", q)
		}
		for _, t := range h.UnattributableLive {
			fmt.Fprintf(stdout, "  held ticket without a dir: %s\n", t)
		}
	}

	// Stray healing UNDER apply.lock, HELD ACROSS the heal loop (round-3
	// fix of the round-2 fold: releasing after TryLock left the heal racing
	// a live probe's millisecond rename window into HardAborts). Held =>
	// skip and say so.
	if healLock, hlerr := lockfile.Open(lockPath); hlerr == nil {
		free, _ := healLock.TryLock()
		if !free {
			healLock.Close()
			fmt.Fprintf(stdout, "stray healing: SKIPPED (apply.lock held by a running apply/discard/prune)\n")
		} else {
			healed := 0
			parked := 0
			for _, r := range config.ExpandRoots(cfg.Roots) {
				entries, derr := os.ReadDir(r)
				if derr != nil {
					continue
				}
				for _, e := range entries {
					if !strings.HasSuffix(e.Name(), ".reap-probing") {
						continue
					}
					stray := filepath.Join(r, e.Name())
					orig := filepath.Join(r, strings.TrimSuffix(e.Name(), ".reap-probing"))
					if _, oerr := os.Stat(orig); os.IsNotExist(oerr) {
						if os.Rename(stray, orig) == nil {
							healed++
						}
					} else {
						dest := stray + ".reap-orphaned-" + time.Now().Format("150405")
						if os.Rename(stray, dest) == nil {
							parked++
						}
					}
				}
			}
			healLock.Close()
			fmt.Fprintf(stdout, "stray .reap-probing dirs healed: %d, parked as .reap-orphaned: %d (restore by renaming back)\n", healed, parked)
		}
	}

	// Per-candidate residue: stranded refs/reap/* pins (a crashed discard
	// leaves them; they hold objects alive and pollute unpushed counts),
	// .reap-backup index pairs (an interrupted capture), and aged
	// index.lock files (the git-busy skip's remedy). BOUNDED (round 11;
	// three rounds of panel findings: a serial for-each-ref over every
	// root child ran 500s+ unfinishable on the real 470-dir layout): an
	// overall deadline, a progress line, and an honest incomplete line
	// when the deadline trips.
	deadline := time.Now().Add(90 * time.Second)
	checked, total := 0, 0
	for _, r := range config.ExpandRoots(cfg.Roots) {
		if entries, derr := os.ReadDir(r); derr == nil {
			total += len(entries)
		}
	}
sweep:
	for _, r := range config.ExpandRoots(cfg.Roots) {
		entries, derr := os.ReadDir(r)
		if derr != nil {
			continue
		}
		for _, e := range entries {
			if time.Now().After(deadline) {
				break sweep
			}
			cand := filepath.Join(r, e.Name())
			// Cheap VCS pre-filter (the R10-12 rel seat): spawning git on
			// every root child burns the budget on guaranteed failures.
			if _, gerr := os.Stat(filepath.Join(cand, ".git")); gerr != nil {
				if _, jerr := os.Stat(filepath.Join(cand, ".jj")); jerr != nil {
					checked++
					continue
				}
			}
			if out, gerr := gr.ForEachReapRef(cand); gerr == nil && len(out) > 0 {
				// Reclaimable bytes: the loose-object store's size (the
				// scoped gc's upper bound for what the stranded pins hold).
				var objBytes int64
				filepath.WalkDir(filepath.Join(cand, ".git", "objects"), func(p string, d os.DirEntry, err error) error {
					if err == nil && !d.IsDir() {
						if fi, ierr := d.Info(); ierr == nil {
							objBytes += fi.Size()
						}
					}
					return nil
				})
				fmt.Fprintf(stdout, "stranded refs/reap/* in %s: %d ref(s), ~%d MB objects; reclaim with: git -C %s update-ref -d <ref> && git -C %s gc --prune=now\n",
					cand, len(out), objBytes>>20, cand, cand)
			}
			g := filepath.Join(r, e.Name(), ".git", "index.lock")
			if fi, gerr := os.Stat(g); gerr == nil && time.Since(fi.ModTime()) > time.Hour {
				fmt.Fprintf(stdout, "aged index.lock: %s (%.0fh old; delete if no git is running)\n", g, time.Since(fi.ModTime()).Hours())
			}
			if _, gerr := os.Stat(filepath.Join(r, e.Name(), ".git", "index.reap-backup")); gerr == nil {
				fmt.Fprintf(stdout, "interrupted capture in %s: .git/index.reap-backup present; if everything is staged, unstage with: git -C %s reset\n", cand, cand)
			}
			checked++
			if checked%32 == 0 {
				fmt.Fprintf(stdout, "residue sweep: %d/%d candidates\n", checked, total)
			}
		}
	}
	if checked < total {
		fmt.Fprintf(stdout, "residue sweep INCOMPLETE: %d of %d candidates checked (90s deadline; the sweep is not resumable yet - the tail needs a longer deadline or pruning)\n", checked, total)
	}
	return ExitOK
}

func quarantineStats(stateDir string) (total int64, oldestDays int) {
	for _, s := range quarantine.List(stateDir) {
		total += quarantine.Bytes(s.Dir)
		if fi, err := os.Stat(s.Dir); err == nil {
			d := int(time.Since(fi.ModTime()).Hours() / 24)
			if d > oldestDays {
				oldestDays = d
			}
		}
	}
	return
}

type ledgerInfo struct {
	bytes      int64
	lines      int
	rotations  int
	span       string
	freeDelta  *int64
	downgraded int
}

func ledgerStats(stateDir string) ledgerInfo {
	var li ledgerInfo
	newest, oldest := time.Time{}, time.Time{}
	// Oldest rotations first so envelopes parse in time order across the
	// rotation boundary.
	var files []string
	for i := 5; i >= 1; i-- {
		p := filepath.Join(stateDir, fmt.Sprintf("reap.log.%d", i))
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
			li.rotations++
		}
	}
	files = append(files, filepath.Join(stateDir, "reap.log"))

	type envelope struct {
		runID string
		after uint64
	}
	var envelopes []envelope
	var lastRunLines []map[string]any
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		li.bytes += int64(len(raw))
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "" {
				continue
			}
			li.lines++
			var row map[string]any
			if json.Unmarshal([]byte(line), &row) != nil {
				continue
			}
			if ts, ok := row["ts"].(string); ok {
				if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
					if oldest.IsZero() || t.Before(oldest) {
						oldest = t
					}
					if newest.IsZero() || t.After(newest) {
						newest = t
					}
				}
			}
			if row["event"] == "envelope" {
				after, _ := row["freeBytesAfter"].(float64)
				runID, _ := row["runId"].(string)
				envelopes = append(envelopes, envelope{runID: runID, after: uint64(after)})
				lastRunLines = nil // a new run closes the window
				continue
			}
			lastRunLines = append(lastRunLines, row)
		}
	}
	if len(envelopes) >= 2 {
		delta := int64(envelopes[len(envelopes)-1].after) - int64(envelopes[len(envelopes)-2].after)
		li.freeDelta = &delta
	}
	// Downgraded = distinct paths in the LAST logged run carrying an
	// ignorance-class reasonCode (gh/jj/git unavailability).
	downgraded := map[string]bool{}
	for _, row := range lastRunLines {
		code, _ := row["reasonCode"].(string)
		switch code {
		case "gh-unavailable", "jj-remote-stale", "facts-unavailable", "state-unreadable", "remote-stale":
			if p, ok := row["path"].(string); ok {
				downgraded[p] = true
			}
		}
	}
	li.downgraded = len(downgraded)
	if !oldest.IsZero() && !newest.IsZero() {
		li.span = fmt.Sprintf("%s to %s", oldest.Format("2006-01-02"), newest.Format("2006-01-02"))
	} else {
		li.span = "(empty)"
	}
	return li
}
