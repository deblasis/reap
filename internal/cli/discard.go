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
	_ = yes
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
			summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{Path: path, Why: applycmd.SkipVerdictChanged})
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

		// Quarantine (unless loudly declined).
		qPath := ""
		mode := "no-quarantine"
		if !*noQuarantine {
			session := quarantine.SessionDir(stateDir, path, time.Now())
			var m *quarantine.Manifest
			m, err = quarantine.Snapshot(session, path, gr, quarantine.Options{Mode: "bundle"})
			if err != nil {
				fmt.Fprintf(stderr, "reap discard: %s: %v (dir untouched)\n", path, err)
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
			Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, Residue: rv.Verdict.BlockedClassFact}
		result.Manifest = rv.Manifest
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
			if !*asJSON {
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
				fmt.Fprintln(stdout, line)
			} else {
				fmt.Fprintln(stdout, line)
			}
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
