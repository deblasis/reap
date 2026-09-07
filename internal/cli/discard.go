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
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/quarantine"
	"github.com/deblasis/reap/internal/verdict"
	"github.com/deblasis/reap/internal/walk"
)

// cmdDiscard implements `reap discard PATH...`: BLOCKED resolution with
// quarantine-then-delete. Input contract (spec): BLOCKED dirs only (a dir
// carrying any BLOCKED-class fact is discard-ELIGIBLE — that is the point);
// SAFE/ACTIVE/KEEP refuse; nested repos refuse naming them. Per path:
// tripwire+probe, snapshot, verify, delete via the apply path, all audited.
func cmdDiscard(args []string, stdout, stderr io.Writer, stdin *os.File) int {
	fs := flag.NewFlagSet("discard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit the machine schema")
	yes := fs.Bool("yes", false, "confirm non-interactively")
	noQuarantine := fs.Bool("no-quarantine", false, "skip the snapshot (interactive TTY confirm required; loud logging)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: reap discard PATH... [--yes] [--no-quarantine] [--json]")
		return ExitUsage
	}

	stateDir, err := config.StateDir()
	if err != nil {
		fmt.Fprintf(stderr, "reap discard: %v\n", err)
		return ExitState
	}
	cfg, err := config.Load(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap discard: %v\n", err)
		return ExitState
	}
	// --no-quarantine is TTY-only over --yes (the mechanical backstop).
	if *noQuarantine && !applycmd.IsTerminal(stdin, stdout) {
		fmt.Fprintln(stderr, "reap discard: --no-quarantine requires an interactive TTY confirm naming what will NOT be captured")
		return applycmd.ExitNotTTY
	}
	// The family confirm: --yes or an interactive TTY, never inferred from
	// EOF; 121 when neither. Quarantine is the ONLY recovery, so the prompt
	// says so, and --no-quarantine sessions name what will NOT be captured.
	if !*yes {
		if !applycmd.IsTerminal(stdin, stdout) {
			fmt.Fprintln(stderr, "reap discard deletes permanently (the quarantine bundle is the only recovery); pass --yes to confirm when not interactive")
			return applycmd.ExitNotTTY
		}
		for _, p := range fs.Args() {
			fmt.Fprintf(stdout, "  discard %s\n", p)
		}
		if *noQuarantine {
			fmt.Fprintln(stdout, "NO quarantine: dirty files, untracked files, stashes and local-only commits will NOT be captured")
		} else {
			fmt.Fprintln(stdout, "each dir is snapshotted to a quarantine bundle first (reap quarantine list shows sessions)")
		}
		fmt.Fprint(stdout, "Proceed? [y/N] ")
		var answer string
		if _, aerr := fmt.Fscanln(stdin, &answer); aerr != nil {
			fmt.Fprintln(stdout, "\ndeclined")
			return ExitOK
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fmt.Fprintln(stdout, "declined")
			return ExitOK
		}
	}

	lock, err := applycmd.Lock(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap discard: %v\n", err)
		return ExitState
	}
	defer lock.Close()

	runID := auditlog.NewRunID()
	log, err := auditlog.Open(stateDir, runID)
	if err != nil {
		fmt.Fprintf(stderr, "reap discard: %v\n", err)
		return ExitState
	}
	freeBefore := auditlog.FreeBytes(stateDir)
	summary := applycmd.Summary{RunID: runID}
	defer func() {
		_ = log.Append(auditlog.Line{Event: "envelope", Deleted: len(summary.Deleted),
			Skipped: len(summary.Skipped), FreeBefore: freeBefore, FreeAfter: auditlog.FreeBytes(stateDir), Quarantine: nil})
	}()
	appendOrAbort := func(line auditlog.Line) int {
		if err := log.Append(line); err != nil {
			fmt.Fprintf(stderr, "reap discard: HARD ABORT: %v\n", err)
			return ExitState
		}
		return -1
	}

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}

	for _, rawPath := range fs.Args() {
		path, aerr := filepath.Abs(rawPath)
		if aerr != nil {
			path = rawPath
		}
		intent := auditlog.Line{Event: "intent", Path: path, Quarantine: nil}
		if rc := appendOrAbort(intent); rc >= 0 {
			return rc
		}

		if !dirExists(path) {
			ok := false
			if rc := appendOrAbort(auditlog.Line{Event: "skip", Path: path, SkipWhy: "missing", OK: &ok, Quarantine: nil}); rc >= 0 {
				return rc
			}
			summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{Path: path, Why: "missing"})
			continue
		}

		// Eligibility: BLOCKED-class fact required (the whole point of
		// discard); re-verify runs the full-strength verdict and demands it.
		rv := applycmd.Reverify(path, "dirty-files", false, cfg, applycmd.Deleter{Git: gr}, config.ExpandRoots(cfg.Protect), nil, nil, nil)
		if rv.Verdict.Verdict != verdict.Blocked || rv.Verdict.BlockedClassFact == "" {
			summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{Path: path,
				Why: fmt.Sprintf("not BLOCKED (fresh verdict %s/%s; discard is the BLOCKED resolver)", rv.Verdict.Verdict, rv.Verdict.Code)})
			ok := false
			if rc := appendOrAbort(auditlog.Line{Event: "skip", Path: path, SkipWhy: "not-blocked",
				Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, OK: &ok, Quarantine: nil}); rc >= 0 {
				return rc
			}
			continue
		}

		// The rename in-use probe: Reverify's BLOCKED early return (the
		// match gate) never reaches its own probe, so discard runs it here —
		// a dir a live process holds open must not be quarantined-then-
		// deleted either. A stranded probe is a hard abort naming the path.
		inUse, perr := applycmd.InUseProbe(path)
		if perr != nil {
			fmt.Fprintf(stderr, "reap discard: HARD ABORT: probe stranded for %s: %v\n", path, perr)
			return ExitState
		}
		if inUse {
			summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{Path: path, Why: applycmd.SkipInUseProbe})
			ok := false
			if rc := appendOrAbort(auditlog.Line{Event: "skip", Path: path, SkipWhy: applycmd.SkipInUseProbe, OK: &ok, Quarantine: nil}); rc >= 0 {
				return rc
			}
			continue
		}

		// Quarantine (unless loudly declined), under the configured cap: an
		// over-cap snapshot refuses the discard with the dir untouched.
		qPath := ""
		mode := "no-quarantine"
		if !*noQuarantine {
			session := quarantine.SessionDir(stateDir, path, time.Now())
			capBytes := int64(cfg.Thresholds.QuarantineCapGB * float64(1<<30))
			m, serr := quarantine.Snapshot(session, path, gr, quarantine.Options{Mode: "bundle", CapBytes: capBytes})
			if serr != nil {
				fmt.Fprintf(stderr, "reap discard: %s: %v (dir untouched)\n", path, serr)
				summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{Path: path, Why: "quarantine-failed"})
				ok := false
				if rc := appendOrAbort(auditlog.Line{Event: "skip", Path: path, SkipWhy: "quarantine-failed", OK: &ok, Quarantine: nil}); rc >= 0 {
					return rc
				}
				continue
			}
			qPath = session
			mode = "quarantine+rm"
			_ = m
		}

		// Manifest capture BEFORE Delete (the M2 lesson, applied at birth
		// here): after removal the path cannot be read. The match gate also
		// returns before manifest capture on a BLOCKED fresh verdict —
		// discard's expected outcome — so rv.Manifest is empty for BLOCKED.
		manifest := walk.CappedManifest(path)

		// Confirmation for the batch happens once, before the loop's deletions
		// (the caller-facing choreography in Confirm covers this path too when
		// --yes is absent).
		cls := classify.Dir(path)
		mode, err = applycmd.Delete(path, cls, applycmd.Deleter{Git: gr})
		if err != nil {
			ok := false
			_ = log.Append(auditlog.Line{Event: "result", Path: path, Mode: mode, OK: &ok, Quarantine: qPtr(qPath)})
			fmt.Fprintf(stderr, "reap discard: deletion failed: %s: %v\n", path, err)
			return applycmd.ExitDeleteFail
		}
		qp := qPtr(qPath)
		result := auditlog.Line{Event: "result", Path: path, Mode: mode, OK: boolPtr(true), Quarantine: qp,
			Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, Residue: rv.Verdict.BlockedClassFact, Manifest: manifest}
		if rv.Git != nil {
			result.Branch = rv.Git.Branch
			result.HeadSHA = rv.Git.HEAD
			result.Dirty, result.Untracked = rv.Git.Dirty, rv.Git.Untracked
		}
		if rc := appendOrAbort(result); rc >= 0 {
			return rc
		}
		summary.Deleted = append(summary.Deleted, path)
	}

	freeAfter := auditlog.FreeBytes(stateDir)
	if freeAfter > freeBefore {
		summary.FreeGain = freeAfter - freeBefore
	}
	if !*asJSON {
		qGB := float64(quarantine.Bytes(quarantine.Dir(stateDir)) / (1 << 20))
		fmt.Fprintf(stdout, "discarded %d dirs (quarantine now %.0f MB; ~0 GB freed until pruned)\n", len(summary.Deleted), qGB)
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

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func qPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func boolPtr(b bool) *bool { return &b }

// cmdLog reads reap.log (and all rotations, oldest first), filtered by --since.
func cmdLog(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	fs.SetOutput(stderr)
	since := fs.Duration("since", 0, "only entries newer than this duration (e.g. 24h)")
	asJSON := fs.Bool("json", false, "emit raw JSONL")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	stateDir, err := config.StateDir()
	if err != nil {
		fmt.Fprintf(stderr, "reap log: %v\n", err)
		return ExitState
	}
	// Rotations oldest-first, then active: reap.log.5 .. reap.log.1, reap.log.
	var files []string
	for i := 5; i >= 1; i-- {
		p := filepath.Join(stateDir, fmt.Sprintf("reap.log.%d", i))
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		}
	}
	files = append(files, filepath.Join(stateDir, "reap.log"))

	cutoff := time.Time{}
	if *since > 0 {
		cutoff = time.Now().Add(-*since)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "" {
				continue
			}
			// --since filters BOTH shapes: raw JSONL is a machine view of
			// the same ledger, not an excuse to ignore the window.
			if cutoff.After(time.Time{}) {
				var probe struct {
					TS string `json:"ts"`
				}
				if json.Unmarshal([]byte(line), &probe) == nil {
					if ts, perr := time.Parse(time.RFC3339Nano, probe.TS); perr == nil && ts.Before(cutoff) {
						continue
					}
				}
			}
			if *asJSON {
				fmt.Fprintln(stdout, line)
				continue
			}
			// Text mode renders human rows; --json is the raw JSONL.
			var row struct {
				TS      string `json:"ts"`
				Event   string `json:"event"`
				Path    string `json:"path"`
				OK      *bool  `json:"ok"`
				SkipWhy string `json:"skipWhy"`
				Deleted int    `json:"deleted"`
				Skipped int    `json:"skipped"`
			}
			if json.Unmarshal([]byte(line), &row) != nil {
				fmt.Fprintln(stdout, line)
				continue
			}
			ts := row.TS
			if len(ts) > 19 {
				ts = ts[:19]
			}
			status := ""
			switch row.Event {
			case "result":
				if row.OK != nil && *row.OK {
					status = "deleted"
				} else {
					status = "FAILED"
				}
			case "skip":
				status = "skip:" + row.SkipWhy
			case "intent":
				status = "begin"
			case "envelope":
				status = fmt.Sprintf("run end: deleted=%d skipped=%d", row.Deleted, row.Skipped)
			}
			fmt.Fprintf(stdout, "%s  %-8s  %-28s  %s\n", ts, row.Event, status, row.Path)
		}
	}
	return ExitOK
}

// cmdQuarantine implements list | prune | restore.
func cmdQuarantine(args []string, stdout, stderr io.Writer) int {
	stateDir, err := config.StateDir()
	if err != nil {
		fmt.Fprintf(stderr, "reap quarantine: %v\n", err)
		return ExitState
	}
	if len(args) == 0 || args[0] == "list" {
		for _, s := range quarantine.List(stateDir) {
			mb := quarantine.Bytes(s.Dir) >> 20
			if s.Manifest == nil {
				fmt.Fprintf(stdout, "%8d MB  %s  (manifest unreadable)\n", mb, s.Dir)
				continue
			}
			fmt.Fprintf(stdout, "%8d MB  %s  mode=%s source=%s\n", mb, s.Dir, s.Manifest.Mode, s.Manifest.Source)
		}
		return ExitOK
	}
	switch args[0] {
	case "prune":
		fs := flag.NewFlagSet("prune", flag.ContinueOnError)
		fs.SetOutput(stderr)
		older := fs.Duration("older-than", 0, "prune sessions older than this duration (default: quarantine-retention-days)")
		yes := fs.Bool("yes", false, "confirm non-interactively")
		if err := fs.Parse(args[1:]); err != nil {
			return ExitUsage
		}
		cfg, err := config.Load(stateDir)
		if err != nil {
			fmt.Fprintf(stderr, "reap quarantine prune: %v\n", err)
			return ExitState
		}
		dur := *older
		if dur == 0 {
			dur = time.Duration(cfg.Thresholds.QuarantineRetentionD) * 24 * time.Hour
		}
		cutoff := time.Now().Add(-dur)
		listing := quarantine.List(stateDir)
		var victims []string
		for _, s := range listing {
			if fi, serr := os.Stat(s.Dir); serr == nil && fi.ModTime().Before(cutoff) {
				victims = append(victims, s.Dir)
			}
		}
		if len(victims) == 0 {
			fmt.Fprintln(stdout, "nothing to prune")
			return ExitOK
		}
		fmt.Fprintf(stdout, "will delete %d bundle(s): recovery for these discards ends here. Proceed? [y/N] ", len(victims))
		if !*yes {
			var answer string
			if _, aerr := fmt.Fscanln(os.Stdin, &answer); aerr != nil {
				fmt.Fprintln(stdout, "\ndeclined")
				return ExitOK
			}
			if !strings.EqualFold(strings.TrimSpace(answer), "y") {
				fmt.Fprintln(stdout, "declined")
				return ExitOK
			}
		}
		removed := quarantine.PruneOlderThan(stateDir, cutoff)
		fmt.Fprintf(stdout, "pruned %d session(s)\n", len(removed))
		return ExitOK
	default:
		fmt.Fprintf(stderr, "reap quarantine: unknown subcommand %q (list | prune)\n", args[0])
		return ExitUsage
	}
}
