package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/applycmd"
	"github.com/deblasis/reap/internal/auditlog"
	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/dedupe"
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/jjx"
	"github.com/deblasis/reap/internal/quarantine"
	"github.com/deblasis/reap/internal/verdict"
	"github.com/deblasis/reap/internal/walk"
)

// discardWork is one path that survived wave-0 rails (missing / reparse /
// held / protected / pure-jj) and enters re-verify + quarantine + delete.
type discardWork struct {
	path string
	cls  classify.Info
	size int64
}

// cmdDiscard implements `reap discard PATH...`: BLOCKED resolution with
// quarantine-then-delete. Eligibility keys on the FULL fact set (any
// BLOCKED-class fact, regardless of the displayed row — this un-strands
// shadowed parents); every other class refuses with a NAMED message (KEEP
// rails unconditionally; orphaned dirs point at the carve-out; nested-repo
// dirs name them; MANUAL/ACTIVE point at plan --include/--override-manual;
// SAFE points at plan/apply). Per path: tripwire + probe, free-space
// preflight at max(cap, measured) x margin, snapshot completely, verify,
// then delete via the same deregister-before-rm path as apply, children
// first, all audited write-ahead.
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
	// --no-quarantine is TTY-only and IGNORES --yes entirely (the spec's
	// mechanical backstop): a non-interactive context cannot even ask the
	// question, which makes the combination a usage error, not a 121.
	if *noQuarantine && !applycmd.IsTerminal(stdin, stdout) {
		fmt.Fprintln(stderr, "reap discard: --no-quarantine requires a live interactive TTY confirm naming what will NOT be captured; non-interactive use is a usage error")
		return ExitUsage
	}

	// Canonical dedupe: the same path twice must not double-delete (the
	// second pass would hit a missing dir and force exit 2).
	var paths []string
	seen := map[string]bool{}
	for _, raw := range fs.Args() {
		p, aerr := filepath.Abs(raw)
		if aerr != nil {
			p = raw
		}
		c := config.Canonical(p)
		if seen[c] {
			continue
		}
		seen[c] = true
		paths = append(paths, p)
	}

	// Wave 0: cheap, deterministic rails (no git) — missing paths, reparse
	// points, holds, protect globs, pure-jj dirs. These need no re-verify.
	var work []discardWork
	refused := false // any input-contract refusal (120-class when nothing was deleted)

	holds := applycmd.ReadHoldsSnapshot(stateDir)
	holdsBool := map[string]bool{}
	for h := range holds {
		holdsBool[h] = true
	}
	protectExpanded := config.ExpandRoots(cfg.Protect)

	for _, path := range paths {
		if !dirExists(path) {
			fmt.Fprintf(stderr, "reap discard: %s: path does not exist\n", path)
			refused = true
			continue // no audit line yet: the ledger is not open
		}
		if rp, rerr := walk.IsReparse(path, nil); rerr == nil && rp {
			fmt.Fprintf(stderr, "reap discard: %s: refused: reparse point (junction/symlink); apply/discard never cross a reparse point\n", path)
			refused = true
			continue
		}
		if applycmd.PathHeld(holdsBool, path) {
			fmt.Fprintf(stderr, "reap discard: %s: refused: held by user (reap holds); holds beat every rule and every flag\n", path)
			refused = true
			continue
		}
		if prot, _ := config.MatchProtect(path, protectExpanded); prot {
			fmt.Fprintf(stderr, "reap discard: %s: refused: matches a protect glob; protected paths beat every rule and every flag\n", path)
			refused = true
			continue
		}
		cls := classify.Dir(path)
		if cls.Kind == classify.KindJJRepo && !cls.GitBackend {
			fmt.Fprintf(stderr, "reap discard: %s: refused: pure jj repo (no colocated git backend); quarantine capture needs the git backend — resolve manually (jj git init --colocate, or push), then discard again\n", path)
			refused = true
			continue
		}
		info := walk.Entry(filepath.Dir(path), path, time.Now())
		work = append(work, discardWork{path: path, cls: cls, size: info.Bytes})
	}

	// The confirm (before any mutation): spec prompt copy naming the
	// destination pattern, the cap on the delta, and the GB at stake.
	// --no-quarantine ALWAYS asks (it ignores --yes); the quarantine mode
	// honors --yes; EOF/Enter declines, never confirms.
	if len(work) > 0 {
		var totalBytes int64
		for _, w := range work {
			totalBytes += w.size
		}
		capGB := cfg.Thresholds.QuarantineCapGB
		if !*noQuarantine {
			if !*yes {
				if !applycmd.IsTerminal(stdin, stdout) {
					fmt.Fprintln(stderr, "reap discard deletes permanently (the quarantine bundle is the only recovery); pass --yes to confirm when not interactive")
					return applycmd.ExitNotTTY
				}
				sample := quarantine.SessionDir(stateDir, work[0].path, time.Now())
				fmt.Fprintf(stdout, "quarantining to %s (cap %.0f GB on the delta), then permanently deleting %.1f GB\n",
					sample, capGB, float64(totalBytes)/(1<<30))
				for _, w := range work {
					fmt.Fprintf(stdout, "  discard %s\n", w.path)
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
		} else {
			// TTY guaranteed by the usage gate above.
			fmt.Fprintln(stdout, "NO quarantine: dirty files, untracked files, ignored files, stashes, unpushed commits (branch and reflog-only), and jj changes will NOT be captured — deletion is UNRECOVERABLE")
			for _, w := range work {
				fmt.Fprintf(stdout, "  discard %s (%.1f GB)\n", w.path, float64(w.size)/(1<<30))
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
	}

	if len(work) == 0 {
		// Every path refused before the ledger opened; nothing was audited
		// or deleted. Input-contract refusals with nothing done: 120.
		return ExitUsage
	}

	// The runId is minted BEFORE the lock so the lock body names the real
	// run (round-2: it always read runId=unknown).
	runID := auditlog.NewRunID()
	lock, err := applycmd.Lock(stateDir, runID)
	if err != nil {
		fmt.Fprintf(stderr, "reap discard: %v\n", err)
		return ExitState
	}
	defer lock.Close()

	// Holds and protect globs are RE-READ under the lock: a hold that
	// landed while the operator sat at the confirm prompt (the lock was
	// free then, and `reap hold` takes it only briefly) must not be
	// invisible to re-verify — holds beat every rule and every flag.
	freshHolds := applycmd.ReadHoldsSnapshot(stateDir)
	for h := range freshHolds {
		holdsBool[h] = true
	}
	for _, w := range work {
		if applycmd.PathHeld(holdsBool, w.path) {
			fmt.Fprintf(stderr, "reap discard: %s: refused: held by user DURING the confirm window (reap hold landed mid-run); rerun discard if this is unexpected\n", w.path)
			refused = true
		}
	}

	log, err := auditlog.Open(stateDir, runID)
	if err != nil {
		fmt.Fprintf(stderr, "reap discard: %v\n", err)
		return ExitState
	}
	freeBefore := auditlog.FreeBytes(stateDir)
	summary := applycmd.Summary{RunID: runID, Planned: pathsOfDiscardWork(work)}
	defer func() {
		_ = log.Append(auditlog.Line{Event: "envelope", Planned: len(work),
			Deleted: len(summary.Deleted), Skipped: len(summary.Skipped),
			FreeBefore: freeBefore, FreeAfter: auditlog.FreeBytes(stateDir), Quarantine: nil})
	}()
	appendOrAbort := func(line auditlog.Line) int {
		if aerr := log.Append(line); aerr != nil {
			fmt.Fprintf(stderr, "reap discard: HARD ABORT: %v\n", aerr)
			return ExitState
		}
		return -1
	}

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	jr := jjx.Runner{Budget: 30 * time.Second}
	capBytes := int64(cfg.Thresholds.QuarantineCapGB * float64(1<<30))
	margin := cfg.Thresholds.QuarantineMargin
	// The quarantine dir may not exist yet on a fresh install (a free-space
	// probe of a missing path reads 0 and refuses EVERYTHING); the state
	// dir exists and sits on the same volume.
	if err := os.MkdirAll(quarantine.Dir(stateDir), 0o755); err != nil {
		fmt.Fprintf(stderr, "reap discard: %v\n", err)
		return ExitState
	}
	qFree := auditlog.FreeBytes(quarantine.Dir(stateDir))
	exitQuarantine := false // any 125-class refusal (over-cap / verify / preflight)

	// Children first (same lineage rule as apply): a parent and its child
	// in one batch must not delete the parent while the child still exists.
	byPath := map[string]discardWork{}
	for _, w := range work {
		byPath[config.Canonical(w.path)] = w
	}
	var ordered []discardWork
	for _, pe := range applycmd.OrderChildrenFirst(planEntriesOf(work)) {
		if w, ok := byPath[config.Canonical(pe.Path)]; ok {
			ordered = append(ordered, w)
		}
	}

	var dirBytes, bundleBytes int64
	// The deletion-set hardlink pass accumulates AS each path is about to
	// be deleted (a post-hoc walk has nothing to walk); one identity map
	// gives set semantics across the whole run.
	reclaim := dedupe.NewCounter(50000)
	for _, w := range ordered {
		path, cls := w.path, w.cls

		// Re-verify seconds before deletion, at full strength, WITH the
		// hold/protect rails joined (round-2 fold: a held dirty dir must
		// verdict KEEP here, not BLOCKED).
		rv := applycmd.Reverify(path, "dirty-files", false, cfg, applycmd.Deleter{Git: gr, JJ: jr}, protectExpanded, holdsBool, nil, nil)
		if rv.HardAbort != "" {
			fmt.Fprintf(stderr, "reap discard: HARD ABORT: %s\n", rv.HardAbort)
			return ExitState
		}

		// Fresh-verdict routing. skipWhy and the --json skipped[].why stay
		// enum-clean; refusal prose rides the Note field. All capture and
		// deletion routing below uses the FRESH classification (rv.Class):
		// a dir whose class changed between waves (jj colocated mid-run,
		// .git swapped) must not be captured with wave-0's assumptions.
		cls = rv.Class
		refuse := func(msg, code string) {
			fmt.Fprintf(stderr, "reap discard: %s: refused: %s\n", path, msg)
			refused = true
			summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{Path: path, Why: applycmd.SkipVerdictChanged, Note: msg})
			ok := false
			if rc := appendOrAbort(auditlog.Line{Event: "skip", Path: path, SkipWhy: applycmd.SkipVerdictChanged,
				Verdict: rv.Verdict.Verdict, ReasonCode: code, OK: &ok, Quarantine: nil}); rc >= 0 {
				return
			}
		}
		skip := func(why string) bool {
			summary.Skipped = append(summary.Skipped, applycmd.SkippedPath{Path: path, Why: why})
			ok := false
			if rc := appendOrAbort(auditlog.Line{Event: "skip", Path: path, SkipWhy: why,
				Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, OK: &ok, Quarantine: nil}); rc >= 0 {
				return false
			}
			return true
		}

		switch {
		case rv.Verdict.Verdict == verdict.Keep:
			refuse("KEEP (held / protected / reparse); KEEP paths refuse unconditionally", rv.Verdict.Code)
			continue
		case cls.Kind == classify.KindGitWorktreeOrphaned || cls.Kind == classify.KindJJWorkspaceOrphaned:
			refuse("orphaned worktree/workspace: capture needs a readable git backend and the parent is gone; the only deletion path is reap apply --override-manual (TTY-only hardened confirm)", rv.Verdict.Code)
			continue
		case rv.SkipWhy == applycmd.SkipParentLive || rv.Verdict.Code == "parent-of-live-children":
			skip(applycmd.SkipParentLive)
			continue
		case rv.SkipWhy == applycmd.SkipActiveTripwire:
			skip(applycmd.SkipActiveTripwire)
			continue
		case rv.SkipWhy == applycmd.SkipIgnorance:
			refuse(fmt.Sprintf("facts unreadable at re-verify (%s); resolve the unreadable state, then retry", rv.Verdict.Code), rv.Verdict.Code)
			continue
		}
		// Eligibility: the FULL fact set, not the displayed row (spec:
		// shadowed parents — dirty-with-live-children etc. — are eligible;
		// the parent-live and nested checks below still gate them).
		if rv.Verdict.BlockedClassFact == "" {
			if rv.Verdict.Verdict == verdict.Safe {
				refuse("SAFE; reap plan/apply is the deletion path for this dir", rv.Verdict.Code)
			} else if rv.Verdict.Verdict == verdict.Active {
				refuse(fmt.Sprintf("ACTIVE (%s); let it idle past the activity window — discard is the BLOCKED resolver, not the activity override", rv.Verdict.Code), rv.Verdict.Code)
			} else {
				refuse(fmt.Sprintf("no BLOCKED-class fact (verdict %s: %s); run reap plan --include %s or reap apply --override-manual",
					rv.Verdict.Verdict, rv.Verdict.Code, rv.Verdict.Code), rv.Verdict.Code)
			}
			continue
		}
		if len(rv.Nested) > 0 {
			refuse(fmt.Sprintf("nested repositories present (%s); resolve the nested repo first", strings.Join(rv.Nested, ", ")), "nested-repositories")
			continue
		}
		if rv.SkipWhy == applycmd.SkipInUseProbe {
			skip(applycmd.SkipInUseProbe)
			continue
		}

		// The intent line lands HERE (round-6 parity with apply): after
		// re-verify, so it carries the fresh residue and nested names, and
		// before ANY mutation — the write-ahead contract is
		// intent-before-DELETION, and the skip/refusal lines above cover
		// everything that did not get this far.
		intent := auditlog.Line{Event: "intent", Path: path, Kind: string(cls.Kind), SizeBytes: w.size, Quarantine: nil}
		if len(rv.Nested) > 0 {
			intent.Residue = "nested: " + strings.Join(rv.Nested, ", ")
		}
		if rc := appendOrAbort(intent); rc >= 0 {
			return rc
		}

		// The rename in-use probe (Reverify's BLOCKED early return never
		// reaches its own probe, so discard runs it here).
		inUse, perr := applycmd.InUseProbe(path)
		if perr != nil {
			fmt.Fprintf(stderr, "reap discard: HARD ABORT: %v\n", perr)
			return ExitState
		}
		if inUse {
			skip(applycmd.SkipInUseProbe)
			continue
		}

		// Free-space preflight: free >= max(cap, measured) * margin. The
		// capture transiently writes roughly the delta twice (staged blobs,
		// then the bundle) on the volume this tool exists to keep alive.
		// Non-git paths (the only !GitBackend eligible shape is a split jj
		// workspace) price against the cap alone — StatusPorcelain is a git
		// probe and would misread them as capture failures.
		if *noQuarantine {
			// No quarantine write is coming, but the AUDIT APPEND still
			// needs its floor (spec: every destructive run preflights).
			if floor := uint64(cfg.Thresholds.MinFreeMB) << 20; qFree < floor {
				fmt.Fprintf(stderr, "reap discard: %s: free space %d MB below the min-free-mb floor (%d MB)\n", path, qFree>>20, floor>>20)
				skip(applycmd.SkipSnapshotOvercap)
				continue
			}
		} else if !cls.GitBackend {
			need := int64(float64(capBytes) * margin)
			if uint64(need) > qFree {
				fmt.Fprintf(stderr, "reap discard: %s: quarantine needs ~%.1f GB, %.1f GB free (the quarantine-cap-gb cap of %.0f GB binds)\n",
					path, float64(need)/(1<<30), float64(qFree)/(1<<30), cfg.Thresholds.QuarantineCapGB)
				exitQuarantine = true
				skip(applycmd.SkipSnapshotOvercap)
				continue
			}
		} else {
			st, serr := gr.StatusPorcelain(path)
			if serr != nil {
				fmt.Fprintf(stderr, "reap discard: %s: %v (dir untouched)\n", path, serr)
				exitQuarantine = true
				skip(applycmd.SkipGitBusy)
				continue
			}
			measured := st.DirtyBytes + st.UntrackedBytes + st.IgnoredBytes
			need := int64(float64(capBytes) * margin)
			capBinds := true
			if measured > capBytes {
				need = int64(float64(measured) * margin)
				capBinds = false
			}
			if uint64(need) > qFree {
				note := ""
				if capBinds {
					note = fmt.Sprintf(" (the quarantine-cap-gb cap of %.0f GB binds)", cfg.Thresholds.QuarantineCapGB)
				}
				fmt.Fprintf(stderr, "reap discard: %s: quarantine needs ~%.1f GB, %.1f GB free%s\n",
					path, float64(need)/(1<<30), float64(qFree)/(1<<30), note)
				exitQuarantine = true
				skip(applycmd.SkipSnapshotOvercap)
				continue
			}
		}

		// Quarantine (unless loudly declined): a fresh, collision-proof
		// session per path (an external same-name creator between the
		// stat and the exclusive Mkdir retries once with a suffixed name).
		qPath := ""
		var qManifest *quarantine.Manifest
		if !*noQuarantine {
			colocated := cls.Kind == classify.KindJJRepo && cls.GitBackend
			var m *quarantine.Manifest
			var qerr error
			session := ""
			for attempt := 0; attempt < 2; attempt++ {
				session = quarantine.FreshSessionDir(stateDir, path, time.Now())
				if !cls.GitBackend {
					// A non-git BLOCKED dir (ignored-content scratch): plain-copy.
					m, qerr = quarantine.WritePlainCopy(session, path, capBytes)
				} else {
					m, qerr = quarantine.Snapshot(session, path, gr, quarantine.Options{
						Mode: "bundle", CapBytes: capBytes, RunID: runID, JJ: jr, Colocated: colocated})
				}
				if qerr == nil || !isSessionExistsErr(qerr) {
					break
				}
			}
			if qerr != nil {
				var tooLarge *quarantine.ErrTooLarge
				var busy *quarantine.ErrGitBusy
				var ver *quarantine.ErrVerify
				switch {
				case errors.As(qerr, &tooLarge):
					fmt.Fprintf(stderr, "reap discard: %s: %v (dir untouched)\n", path, qerr)
					exitQuarantine = true
					skip(applycmd.SkipSnapshotOvercap)
				case errors.As(qerr, &busy):
					fmt.Fprintf(stderr, "reap discard: %s: %v (dir untouched)\n", path, qerr)
					skip(applycmd.SkipGitBusy)
				case errors.As(qerr, &ver):
					// Hard error naming WHERE the captured content provably
					// lives: the actual pinned refs, not just the namespace.
					refs, _ := gr.ForEachReapRef(path)
					named := strings.Join(refs, ", ")
					if named == "" {
						named = "refs/reap/*"
					}
					fmt.Fprintf(stderr, "reap discard: %s: bundle verify FAILED — the captured content provably lives at %s inside %s (dir untouched); recover manually before discarding\n", path, named, path)
					ok := false
					_ = log.Append(auditlog.Line{Event: "result", Path: path, Mode: "verify-failed", OK: &ok,
						Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, Quarantine: nil,
						Residue: "bundle verify failed; content at " + named})
					return applycmd.ExitQuarantine
				default:
					// Generic capture failure: quarantine-family refusal,
					// 125 band, dir untouched (a skip line's closed enum has
					// no bucket for it; a result ok=false line records it).
					fmt.Fprintf(stderr, "reap discard: %s: %v (dir untouched)\n", path, qerr)
					exitQuarantine = true
					ok := false
					if rc := appendOrAbort(auditlog.Line{Event: "result", Path: path, OK: &ok,
						Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, Quarantine: nil,
						Residue: "capture failed: " + qerr.Error()}); rc >= 0 {
						return rc
					}
				}
				continue
			}
			qPath = session
			qManifest = m
			if m != nil && m.BundleBytes > 0 {
				// The preflight window narrows as the run consumes the
				// volume: later paths check against what is actually left.
				// Underflow-guarded: external consumers can drop free below
				// the bundle size mid-run, and a wrapped uint64 passes every
				// later preflight vacuously.
				if m.BundleBytes >= int64(qFree) {
					qFree = 0
				} else {
					qFree -= uint64(m.BundleBytes)
				}
			}
		}

		// Manifest capture BEFORE Delete (the M2 lesson): after removal the
		// path cannot be read. The dedupe pass walks it now too.
		manifest := walk.CappedManifest(path)
		reclaim.Add(path)

		deleteMode, derr := applycmd.Delete(path, cls, applycmd.Deleter{Git: gr, JJ: jr})
		if derr != nil {
			ok := false
			mode := deleteMode
			if *noQuarantine {
				mode = "no-quarantine"
			}
			_ = log.Append(auditlog.Line{Event: "result", Path: path, Mode: mode, OK: &ok, Quarantine: qPtr(qPath), Manifest: manifest})
			fmt.Fprintf(stderr, "reap discard: deletion failed: %s: %v\n", path, derr)
			return applycmd.ExitDeleteFail
		}
		dirBytes += w.size
		mode := deleteMode
		if *noQuarantine {
			// The run still logs mode=no-quarantine (the spec: the mode is
			// never silently rewritten to the deletion mechanism).
			mode = "no-quarantine"
		} else if qManifest != nil {
			bundleBytes += qManifest.BundleBytes
		}
		result := auditlog.Line{Event: "result", Path: path, Mode: mode, SizeBytes: w.size, OK: boolPtr(true),
			Quarantine: qPtr(qPath), Verdict: rv.Verdict.Verdict, ReasonCode: rv.Verdict.Code, Manifest: manifest}
		var notes []string
		if qManifest != nil {
			if qManifest.Interleaved {
				notes = append(notes, "index interleaving detected during capture")
			}
			if qManifest.Mode == "plain-copy" {
				notes = append(notes, "plain copy: files only, no git objects")
			}
			notes = append(notes, "rescued: "+rv.Verdict.BlockedClassFact)
		}
		result.Residue = strings.Join(notes, "; ")
		if rv.Git != nil {
			result.Branch = rv.Git.Branch
			result.HeadSHA = rv.Git.HEAD
			result.Dirty, result.Untracked = rv.Git.Dirty, rv.Git.Untracked
		}
		if rc := appendOrAbort(result); rc >= 0 {
			return rc
		}
		summary.Deleted = append(summary.Deleted, path)
		summary.DeletedBytes += w.size
	}

	freeAfter := auditlog.FreeBytes(stateDir)
	if freeAfter > freeBefore {
		summary.FreeGain = freeAfter - freeBefore
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
	} else {
		// The two-number truth, derived from the deletion-set hardlink
		// pass: hardlinked content shared within the set (zig lane caches)
		// reclaims once, not per dir. Skipped pass -> logical + caveat.
		reclaimExpected := reclaim.Expected
		if reclaim.Over() {
			reclaimExpected = dirBytes
		}
		freedNow := reclaimExpected - bundleBytes
		if freedNow < 0 {
			freedNow = 0
		}
		caveat := ""
		if reclaim.Over() {
			caveat = " (logical; hardlink pass skipped)"
		}
		fmt.Fprintf(stdout, "discarded %d dirs; freed ~%.1f GB now (dir %.1f GB, bundle %.1f GB kept%s); %.1f GB more once the quarantine is pruned\n",
			len(summary.Deleted), float64(freedNow)/(1<<30), float64(dirBytes)/(1<<30), float64(bundleBytes)/(1<<30), caveat, float64(bundleBytes)/(1<<30))
		for _, s := range summary.Skipped {
			note := s.Note
			if note == "" {
				note = s.Why
			}
			fmt.Fprintf(stdout, "  skipped %s: %s\n", s.Path, note)
		}
	}
	switch {
	case exitQuarantine:
		return applycmd.ExitQuarantine
	case len(summary.Deleted) == 0 && refused:
		return ExitUsage
	case len(summary.Skipped) > 0:
		return applycmd.ExitWithSkips
	}
	return applycmd.ExitOK
}

func pathsOfDiscardWork(work []discardWork) []string {
	out := make([]string, 0, len(work))
	for _, w := range work {
		out = append(out, w.path)
	}
	return out
}

func planEntriesOf(work []discardWork) []applycmd.PlanEntry {
	out := make([]applycmd.PlanEntry, 0, len(work))
	for _, w := range work {
		out = append(out, applycmd.PlanEntry{Path: w.path, Kind: string(w.cls.Kind), ParentRepo: w.cls.ParentRepo, SizeBytes: w.size})
	}
	return out
}

// isSessionExistsErr reports a Snapshot refusal caused by the session dir
// already existing (an external creator won the name race). TYPED match
// (round 4): the old prose substring also burned the retry on unrelated
// mkdir failures like access-denied.
func isSessionExistsErr(err error) bool {
	var exists *quarantine.ErrSessionExists
	return errors.As(err, &exists)
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
func cmdQuarantine(args []string, stdout, stderr io.Writer, stdin *os.File) int {
	stateDir, err := config.StateDir()
	if err != nil {
		fmt.Fprintf(stderr, "reap quarantine: %v\n", err)
		return ExitState
	}
	if len(args) == 0 || args[0] == "list" {
		return quarantineList(stateDir, args, stdout, stderr)
	}
	switch args[0] {
	case "prune":
		return quarantinePrune(stateDir, args, stdout, stderr, stdin)
	case "restore":
		return quarantineRestore(stateDir, args, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "reap quarantine: unknown subcommand %q (list | prune | restore)\n", args[0])
		return ExitUsage
	}
}

func quarantineList(stateDir string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit the machine schema")
	if err := fs.Parse(argsForSub(args)); err != nil {
		return ExitUsage
	}
	gr := gitx.Runner{GitBudget: 15 * time.Second, FetchBudget: 15 * time.Second}
	cfg, cfgErr := config.Load(stateDir)
	type row struct {
		Session     string             `json:"session"`
		Bytes       int64              `json:"bytes"`
		AgeDays     int                `json:"ageDays"`
		Mode        string             `json:"mode,omitempty"`
		Source      string             `json:"source,omitempty"`
		SelfContained *bool            `json:"selfContained,omitempty"`
		BaseRef     string             `json:"baseRef,omitempty"`
		BaseSHA     string             `json:"baseSha,omitempty"`
		Origin      string             `json:"origin,omitempty"`
		State       string             `json:"state,omitempty"` // verified-ok | at-risk | unverified
		RunID       string             `json:"runId,omitempty"`
		PastRetention bool             `json:"pastRetention"`
		ManifestOK  bool               `json:"manifestOk"`
	}
	var rows []row
	for _, s := range quarantine.List(stateDir) {
		fi, serr := os.Stat(s.Dir)
		age := 0
		if serr == nil {
			age = int(time.Since(fi.ModTime()).Hours() / 24)
		}
		r := row{Session: s.Dir, Bytes: quarantine.Bytes(s.Dir), AgeDays: age, ManifestOK: s.Manifest != nil}
		if s.Manifest != nil {
			r.Mode, r.Source, r.BaseRef, r.BaseSHA, r.Origin, r.RunID = s.Manifest.Mode, s.Manifest.Source, s.Manifest.BaseRef, s.Manifest.BaseSHA, s.Manifest.Origin, s.Manifest.RunID
			r.SelfContained = &s.Manifest.SelfContained
			r.State = string(quarantine.Revalidate(gr, s.Manifest))
		}
		if cfgErr == nil && age >= cfg.Thresholds.QuarantineRetentionD {
			r.PastRetention = true
		}
		rows = append(rows, r)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
		return ExitOK
	}
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "no quarantine sessions")
		return ExitOK
	}
	for _, r := range rows {
		if !r.ManifestOK {
			hasBundle := false
			if _, serr := os.Stat(filepath.Join(r.Session, "bundle.git")); serr == nil {
				hasBundle = true
			}
			note := "interrupted capture; verify with git bundle verify before trusting"
			if hasBundle {
				note = "manifest unreadable; bundle may still restore"
			}
			fmt.Fprintf(stdout, "%6d MB  %3dd  %s  (%s)\n", r.Bytes>>20, r.AgeDays, filepath.Base(r.Session), note)
			continue
		}
		shape := "delta"
		if r.SelfContained != nil && *r.SelfContained {
			shape = "self-contained"
		}
		mark := ""
		if r.PastRetention {
			mark = "  [past retention: reap quarantine prune]"
		}
		base := ""
		if r.SelfContained != nil && !*r.SelfContained && r.BaseSHA != "" {
			short := r.BaseSHA
			if len(short) > 10 {
				short = short[:10]
			}
			base = " base=" + short
		}
		fmt.Fprintf(stdout, "%6d MB  %3dd  %s  %s%s source=%s state=%s%s\n  restore: reap quarantine restore %s\n",
			r.Bytes>>20, r.AgeDays, filepath.Base(r.Session), shape, base, r.Source, stateLabel(r.State), mark, filepath.Base(r.Session))
	}
	return ExitOK
}

func stateLabel(s string) string {
	switch s {
	case "verified-ok":
		return "verified-ok"
	case "at-risk":
		return "AT-RISK (base gone on remote; recovery through the remote is ending)"
	case "unverified":
		return "unverified (could not reach the remote)"
	}
	return s
}

func argsForSub(args []string) []string {
	if len(args) > 1 {
		return args[1:]
	}
	return nil
}

func quarantinePrune(stateDir string, args []string, stdout, stderr io.Writer, stdin *os.File) int {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	older := fs.Duration("older-than", 0, "prune sessions older than this duration (default: quarantine-retention-days)")
	yes := fs.Bool("yes", false, "confirm non-interactively")
	asJSON := fs.Bool("json", false, "emit the machine schema (confirmation choreography unchanged)")
	if err := fs.Parse(argsForSub(args)); err != nil {
		return ExitUsage
	}
	cfg, err := config.Load(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap quarantine prune: %v\n", err)
		return ExitState
	}
	// apply.lock is held for the whole of apply, discard AND prune: a prune
	// racing a discard must not delete the session that run just wrote.
	lock, lerr := applycmd.Lock(stateDir, "prune")
	if lerr != nil {
		fmt.Fprintf(stderr, "reap quarantine prune: %v\n", lerr)
		return ExitState
	}
	defer lock.Close()

	dur := *older
	if dur == 0 {
		dur = time.Duration(cfg.Thresholds.QuarantineRetentionD) * 24 * time.Hour
	}
	cutoff := time.Now().Add(-dur)
	gr := gitx.Runner{GitBudget: 15 * time.Second, FetchBudget: 15 * time.Second}
	type victim struct {
		dir   string
		size  int64
		ageD  int
		state quarantine.RestoreVerdict
	}
	var victims []victim
	var totalBytes int64
	oldest := 0
	for _, s := range quarantine.List(stateDir) {
		fi, serr := os.Stat(s.Dir)
		if serr != nil || !fi.ModTime().Before(cutoff) {
			continue
		}
		age := int(time.Since(fi.ModTime()).Hours() / 24)
		size := quarantine.Bytes(s.Dir)
		st := quarantine.Revalidate(gr, s.Manifest)
		victims = append(victims, victim{dir: s.Dir, size: size, ageD: age, state: st})
		totalBytes += size
		if age > oldest {
			oldest = age
		}
	}
	if len(victims) == 0 {
		fmt.Fprintln(stdout, "nothing to prune")
		return ExitOK
	}
	atRisk, unverified := false, false
	for _, v := range victims {
		switch v.state {
		case quarantine.AtRisk:
			atRisk = true
		case quarantine.Unverified:
			unverified = true
		}
	}
	// Prune copy follows the revalidation states exactly (spec): at-risk
	// gets the loud warning, unverified gets the offline caveat, verified-ok
	// gets neither.
	warning := "recovery for these discards ends here"
	if atRisk {
		warning = "DELETING ENDS THE LAST RECOVERABLE COPY (at least one bundle's base is gone from its remote)"
		if unverified {
			warning += "; could not verify the base of others (offline?)"
		}
	} else if unverified {
		warning = "recovery for these discards ends here; could not verify the base (offline?); if the base is gone, deleting ends recovery"
	}
	fmt.Fprintf(stdout, "will delete %d bundle(s) (%.1f GB, oldest %dd): %s. Proceed? [y/N] ",
		len(victims), float64(totalBytes)/(1<<30), oldest, warning)
	if !*yes {
		// Non-interactive prune must REFUSE (121), never EOF-decline to 0:
		// "declined" in an agent context would read as nothing-to-do.
		if !applycmd.IsTerminal(stdin, stdout) {
			fmt.Fprintln(stdout, "")
			fmt.Fprintln(stderr, "reap quarantine prune deletes recovery bundles; pass --yes to confirm when not interactive")
			return applycmd.ExitNotTTY
		}
		var answer string
		if _, aerr := fmt.Fscanln(stdin, &answer); aerr != nil {
			fmt.Fprintln(stdout, "\ndeclined")
			return ExitOK
		}
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			fmt.Fprintln(stdout, "declined")
			return ExitOK
		}
	}
	results := quarantine.PruneOlderThan(stateDir, cutoff)
	pruned, failed := 0, 0
	for _, r := range results {
		if r.Err != nil {
			failed++
			fmt.Fprintf(stderr, "reap quarantine prune: failed to delete %s: %v\n", r.Dir, r.Err)
			continue
		}
		pruned++
	}
	// The exit band is computed ONCE, after either output format: --json
	// changes only the format, never the choreography (round-2: it exited
	// 0 on per-bundle failures).
	exit := ExitOK
	if failed > 0 {
		exit = applycmd.ExitQuarantine
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		_ = enc.Encode(map[string]any{"pruned": pruned, "failed": failed, "bytes": totalBytes})
		return exit
	}
	fmt.Fprintf(stdout, "pruned %d session(s)\n", pruned)
	return exit
}

// quarantineRestore is the first-class recovery command, mode-dispatched
// from the manifest: bundle sessions FETCH THE BASE FIRST (a delta whose
// base is merely advanced, not gone, still restores — tips-contains was
// the wrong predicate and refused routine advancement), then the pinned
// refs and the capture; plain-copy sessions copy the files back. Recovery
// never deletes or overwrites anything at the destination. Runs under
// apply.lock: a confirmed prune racing this fetch would delete the
// session mid-restore.
func quarantineRestore(stateDir string, args []string, stdout, stderr io.Writer) int {
	// Manual scan (flags may appear before or after the session id —
	// flag.Parse stops at the first positional).
	var id, to string
	asJSON := false
	positional := argsForSub(args)
	for i := 0; i < len(positional); i++ {
		a := positional[i]
		switch {
		case a == "--to" && i+1 < len(positional):
			to = positional[i+1]
			i++
		case strings.HasPrefix(a, "--to="):
			to = strings.TrimPrefix(a, "--to=")
		case a == "--json":
			asJSON = true
		case id == "":
			id = a
		}
	}
	if id == "" {
		fmt.Fprintln(stderr, "usage: reap quarantine restore <session> [--to PATH] [--json]")
		return ExitUsage
	}
	lock, lerr := applycmd.Lock(stateDir, "restore")
	if lerr != nil {
		fmt.Fprintf(stderr, "reap quarantine restore: %v\n", lerr)
		return ExitState
	}
	defer lock.Close()
	emit := func(v any) {
		if asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(v)
		}
	}
	var session *quarantine.Session
	listing := quarantine.List(stateDir)
	for i := range listing {
		if filepath.Base(listing[i].Dir) == id || listing[i].Dir == id {
			session = &listing[i]
			break
		}
	}
	if session == nil {
		fmt.Fprintf(stderr, "reap quarantine restore: no session %q (reap quarantine list)\n", id)
		return ExitUsage
	}
	if session.Manifest == nil {
		fmt.Fprintf(stderr, "reap quarantine restore: %s: manifest unreadable; bundle: %s (verify with git bundle verify, then git fetch '<bundle>' 'refs/reap/*:refs/reap/*' manually)\n",
			id, filepath.Join(session.Dir, "bundle.git"))
		return ExitState
	}
	m := session.Manifest
	dest := to
	if dest == "" {
		dest = m.Source
	}
	// Recovery never overwrites: a non-empty destination names what is there.
	if entries, rerr := os.ReadDir(dest); rerr == nil && len(entries) > 0 {
		fmt.Fprintf(stderr, "reap quarantine restore: %s exists and is non-empty (recovery never deletes or overwrites; contents: %d entries)\n", dest, len(entries))
		return ExitUsage
	}
	if m.Mode == "plain-copy" {
		if err := restorePlainCopy(session.Dir, dest, m); err != nil {
			fmt.Fprintf(stderr, "reap quarantine restore: %v\n", err)
			return ExitState
		}
		fmt.Fprintf(stdout, "restored %s -> %s (plain copy)\n", id, dest)
		emit(map[string]any{"session": id, "to": dest, "mode": "plain-copy"})
		return ExitOK
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		fmt.Fprintf(stderr, "reap quarantine restore: %v\n", err)
		return ExitState
	}
	wireInitRestore(stderr, dest)
	bundle := filepath.Join(session.Dir, "bundle.git")
	// Delta bundles: FETCH the remote first, then verify each recorded
	// prerequisite EXISTS in the destination (cat-file -e). The remote's
	// tips having moved past the base is routine advancement, not a gone
	// base — refuse only when the object is truly absent, naming the
	// exact SHAs.
	var prereqs []string
	if !m.SelfContained {
		if m.BaseSHA != "" {
			prereqs = append(prereqs, m.BaseSHA)
		}
		for _, b := range m.BaseBases {
			prereqs = append(prereqs, b.SHA)
		}
	}
	if len(prereqs) > 0 && m.Origin != "" {
		if err := fetchRemote(dest, m.Origin, prereqs); err != nil {
			fmt.Fprintf(stderr, "reap quarantine restore: fetching base from %s: %v (prerequisites: %s)\n",
				m.Origin, err, strings.Join(prereqs, ", "))
			return ExitState
		}
		for _, sha := range prereqs {
			if err := execGit(dest, "cat-file", "-e", sha+"^{commit}"); err != nil {
				fmt.Fprintf(stderr, "reap quarantine restore: prerequisite commit %s is absent from %s (the remote no longer carries it); obtain it, then: git -C %s fetch %s 'refs/reap/*:refs/reap/*'\n",
					sha, m.Origin, dest, bundle)
				return ExitState
			}
		}
	}
	if err := fetchBundle(dest, bundle); err != nil {
		fmt.Fprintf(stderr, "reap quarantine restore: fetching bundle: %v (prerequisites: %s)\n", err, strings.Join(prereqs, ", "))
		return ExitState
	}
	if m.CaptureRef != "" {
		if err := execGit(dest, "reset", "-q", "--hard", m.CaptureRef); err != nil {
			fmt.Fprintf(stderr, "reap quarantine restore: materializing capture: %v\n", err)
			return ExitState
		}
	}
	for _, d := range m.EmptyDirs {
		if err := os.MkdirAll(filepath.Join(dest, d), 0o755); err != nil {
			fmt.Fprintf(stderr, "reap quarantine restore: recreating empty dir %s: %v\n", d, err)
		}
	}
	fmt.Fprintf(stdout, "restored %s -> %s (capture ref %s materialized; pinned refs under refs/reap/*)\n", id, dest, m.CaptureRef)
	emit(map[string]any{"session": id, "to": dest, "mode": "bundle", "captureRef": m.CaptureRef})
	return ExitOK
}

func fetchRemote(dest, origin string, prereqs []string) error {
	// Fetch ONLY the recorded prerequisite SHAs first (fetching the whole
	// remote cloned the world for a small delta); fall back to the branch
	// set when the server refuses direct SHA wants.
	if len(prereqs) > 0 {
		args := append([]string{"fetch", "-q", origin}, prereqs...)
		if err := execGit(dest, args...); err == nil {
			return nil
		}
	}
	return execGit(dest, "fetch", "-q", origin, "+refs/heads/*:refs/remotes/restore/*")
}

func fetchBundle(dest, bundle string) error {
	return execGit(dest, "fetch", "-q", bundle, "refs/reap/*:refs/reap/*")
}

func wireInitRestore(_ io.Writer, dir string) {
	_ = execGit(dir, "init", "-q", "-b", "main")
}

// execGit runs git for restore under the FETCH BUDGET (round 4: the one
// unbudgeted exec in the codebase ran while holding apply.lock — a wedged
// endpoint would hold the global state lock forever).
func execGit(dir string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=reap", "GIT_AUTHOR_EMAIL=reap@reap",
		"GIT_COMMITTER_NAME=reap", "GIT_COMMITTER_EMAIL=reap@reap")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("git %v: timeout after 120s", args)
	}
	if err != nil {
		return fmt.Errorf("git %v: %v: %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func restorePlainCopy(sessionDir, dest string, m *quarantine.Manifest) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	files := filepath.Join(sessionDir, "files")
	if _, err := os.Stat(files); err != nil {
		return fmt.Errorf("plain-copy session has no files dir: %w", err)
	}
	return filepath.WalkDir(files, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == files {
			return err
		}
		rel, rerr := filepath.Rel(files, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		// Streamed: a near-cap single file must not spike RSS by its size.
		in, oerr := os.Open(p)
		if oerr != nil {
			return oerr
		}
		defer in.Close()
		out, cerr := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if cerr != nil {
			return cerr
		}
		if _, cerr = io.Copy(out, in); cerr != nil {
			out.Close()
			return cerr
		}
		return out.Close()
	})
}
