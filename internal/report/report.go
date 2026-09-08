// Package report renders a scan: the JSON schema that agents consume and
// the terminal table that humans act on. The table's shape is the design
// spec's mock  -  ACTIVE first (nothing to decide), BLOCKED second (the
// resolution queue IS the product), SAFE last as the payoff  -  and every
// BLOCKED row carries a resolve hint, because a queue without verbs is a
// list.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Entry is one directory in a scan (the scan --json "entries" element).
// openPR always serializes and the nullable fields serialize as null (not
// omitted), per the spec's schema example: consumers must never distinguish
// "absent" from "false"/"none".
type Entry struct {
	Path               string     `json:"path"`
	Zone               string     `json:"zone"`
	Kind               string     `json:"kind"`
	SizeBytes          int64      `json:"sizeBytes"`
	SizePartial        bool       `json:"sizePartial"`
	LastActivity       *time.Time `json:"lastActivity"` // null for reparse candidates (never walked)
	AgeDays            int        `json:"ageDays"`
	ClampedFiles       int        `json:"clampedFiles"`
	Verdict            string     `json:"verdict"`
	ReasonCode         string     `json:"reasonCode"`
	Reason             string     `json:"reason"`
	Hint               string     `json:"hint"`
	Branch             string     `json:"branch,omitempty"`
	Origin             string     `json:"origin,omitempty"`
	Dirty              int        `json:"dirty,omitempty"`
	Untracked          int        `json:"untracked,omitempty"`
	Ignored            int        `json:"ignored,omitempty"`
	Stashes            int        `json:"stashes,omitempty"`
	Unpushed           int        `json:"unpushed,omitempty"`
	UnpushedReflogOnly int        `json:"unpushedReflogOnly,omitempty"`
	OpenPR             bool       `json:"openPR"`
	LineageGroup       *string    `json:"lineageGroup"`
	Held               bool       `json:"held"`
	DowngradedBy       *string    `json:"downgradedBy"`
	BlockedClassFact   string     `json:"blockedClassFact,omitempty"`
	OrphanedCarveOut   bool       `json:"orphanedCarveOut,omitempty"`
	// LastIncoda is the attribution enrichment (spec data model): the dir's
	// most recent incoda activity, null when no record exists (the row then
	// renders the explicit 'no incoda record').
	LastIncoda *Incoda `json:"lastIncoda"`
}

// Incoda is the per-entry attribution detail (ago, owner, reason). The
// fields serialize PRESENT (no omitempty): a null owner and a present
// owner are different facts, and the schema shows both keys.
type Incoda struct {
	Ago    string `json:"ago"`
	Owner  string `json:"owner"`
	Reason string `json:"reason"`
}

// RootSummary aggregates one scanned root.
type RootSummary struct {
	Path   string  `json:"path"`
	Dirs   int     `json:"dirs"`
	SizeGB float64 `json:"sizeGB"`
}

// ReasonTotal is one line of the per-reasonCode breakdown: bucket inflation
// (one row quietly owning half of MANUAL) must be visible, not discovered.
type ReasonTotal struct {
	Code   string  `json:"code"`
	Dirs   int     `json:"dirs"`
	SizeGB float64 `json:"sizeGB"`
}

// Totals completes the schema. ReclaimableGB is null until the hardlink
// dedupe pass runs (plan/apply time), and the caveat prints either way:
// sizes are logical, and zig's central cache shares bytes.
type Totals struct {
	ActiveGB      float64       `json:"activeGB"`
	BlockedGB     float64       `json:"blockedGB"`
	ManualGB      float64       `json:"manualGB"`
	KeepGB        float64       `json:"keepGB"`
	SafeGB        float64       `json:"safeGB"`
	ReclaimableGB *float64      `json:"reclaimableGB"`
	Sizes         string        `json:"sizes"`
	ByReason      []ReasonTotal `json:"byReason"`
	Errors        int           `json:"errors"`
}

// ScanReport is the whole scan --json document.
type ScanReport struct {
	Generated       time.Time     `json:"generated"`
	Roots           []RootSummary `json:"roots"`
	Entries         []Entry       `json:"entries"`
	Excluded        int           `json:"excludedBelowMinGB"`
	UnreadableRoots []string      `json:"unreadableRoots"`
	Totals          Totals        `json:"totals"`
}

func gb(b int64) float64 { return float64(b) / (1 << 30) }

// Build assembles a report from entries (already verdicted). minGB filters
// what is LISTED, never what is counted: totals always describe the full
// scan, so an agent reading --json cannot mistake a display floor for the
// truth (the spec's --min-gb contract).
func Build(now time.Time, roots []RootSummary, entries []Entry, minGB float64) *ScanReport {
	r := &ScanReport{Generated: now, Roots: roots, Totals: Totals{Sizes: "logical"}}
	byCode := map[string]*ReasonTotal{}
	for _, e := range entries {
		if e.SizePartial {
			r.Totals.Errors++
		}
		size := gb(e.SizeBytes)
		switch e.Verdict {
		case "ACTIVE":
			r.Totals.ActiveGB += size
		case "BLOCKED":
			r.Totals.BlockedGB += size
		case "MANUAL":
			r.Totals.ManualGB += size
		case "KEEP":
			r.Totals.KeepGB += size
		case "SAFE":
			r.Totals.SafeGB += size
		}
		bt := byCode[e.ReasonCode]
		if bt == nil {
			bt = &ReasonTotal{Code: e.ReasonCode}
			byCode[e.ReasonCode] = bt
		}
		bt.Dirs++
		bt.SizeGB += size

		if minGB > 0 && size < minGB {
			r.Excluded++
			continue
		}
		r.Entries = append(r.Entries, e)
	}
	for _, bt := range byCode {
		r.Totals.ByReason = append(r.Totals.ByReason, *bt)
	}
	sort.Slice(r.Totals.ByReason, func(i, j int) bool {
		if r.Totals.ByReason[i].SizeGB != r.Totals.ByReason[j].SizeGB {
			return r.Totals.ByReason[i].SizeGB > r.Totals.ByReason[j].SizeGB
		}
		return r.Totals.ByReason[i].Code < r.Totals.ByReason[j].Code
	})
	rd := func(v float64) float64 { return float64(int(v*10)) / 10 }
	r.Totals.ActiveGB = rd(r.Totals.ActiveGB)
	r.Totals.BlockedGB = rd(r.Totals.BlockedGB)
	r.Totals.ManualGB = rd(r.Totals.ManualGB)
	r.Totals.KeepGB = rd(r.Totals.KeepGB)
	r.Totals.SafeGB = rd(r.Totals.SafeGB)
	return r
}

// JSON writes the machine schema.
func (r *ScanReport) JSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

const maxRowsPerSection = 15

// Table renders the human view: fixed section order, size-desc rows, hints
// on BLOCKED and MANUAL rows, elision past 15 rows, and the footers.
func (r *ScanReport) Table(w io.Writer) {
	var totalGB, totalDirs float64
	for _, root := range r.Roots {
		totalDirs += float64(root.Dirs)
		totalGB += root.SizeGB
	}
	fmt.Fprintf(w, "reap scan%74s\n", r.Generated.Format("2006-01-02 15:04"))
	fmt.Fprintf(w, "roots: %-60s %d dirs, %.1f GB logical\n\n",
		strings.Join(rootPaths(r.Roots), " "), int(totalDirs), totalGB)

	sections := []struct {
		name, subtitle string
		entries        []Entry
	}{
		{"ACTIVE", "touched <48h; nothing to decide", r.of("ACTIVE")},
		{"BLOCKED", "waiting on you: push or discard", r.of("BLOCKED")},
		{"MANUAL", "judgment calls (run reap plan --include <code> to widen)", r.of("MANUAL")},
		{"KEEP", "held or protected", r.of("KEEP")},
		{"SAFE", "ready to reap: reap plan, then reap apply", r.of("SAFE")},
	}
	for _, s := range sections {
		if len(s.entries) == 0 {
			continue
		}
		var sizeGB float64
		for _, e := range s.entries {
			sizeGB += gb(e.SizeBytes)
		}
		fmt.Fprintf(w, "%-7s %d dirs %6.1f GB   %s\n", s.name, len(s.entries), sizeGB, dim(s.subtitle))
		shown := s.entries
		if len(shown) > maxRowsPerSection {
			shown = shown[:maxRowsPerSection]
		}
		for _, e := range shown {
			fmt.Fprintf(w, "%7.1f GB  %-44s %s\n", gb(e.SizeBytes), truncate(e.Path, 44), e.Reason)
			// The 'last:' detail, mock-worded: owner, compact ago, %q reason
			// (spec L447: 'last: sess-42, 2h, "seam930 verify"'); the
			// explicit 'last: no incoda record' on eligible rows without one.
			if e.LastIncoda != nil {
				last := e.LastIncoda.Owner
				if last == "" {
					last = "-"
				}
				last += ", " + e.LastIncoda.Ago
				if e.LastIncoda.Reason != "" {
					last += fmt.Sprintf(", %q", e.LastIncoda.Reason)
				}
				fmt.Fprintf(w, "         %s\n", dim("last: "+last))
			} else if s.name == "ACTIVE" || s.name == "BLOCKED" || s.name == "MANUAL" {
				fmt.Fprintf(w, "         %s\n", dim("last: no incoda record"))
			}
			if e.Hint != "" && (s.name == "BLOCKED" || s.name == "MANUAL") {
				fmt.Fprintf(w, "         %s\n", dim("hint: "+e.Hint))
			}
		}
		if rest := len(s.entries) - len(shown); rest > 0 {
			fmt.Fprintf(w, "  %s\n", dim(fmt.Sprintf("+%d more, use --json", rest)))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%s\n", dim("sizes are logical; hardlinked content may reclaim less (zig lane cache shares bytes)"))
	// Per-reason breakdown in the printed totals too: bucket inflation (one
	// row quietly owning half of MANUAL) must be visible to the human at the
	// screen, not only to agents reading --json.
	for _, bt := range r.Totals.ByReason {
		fmt.Fprintf(w, "%7.1f GB  %-24s %d dirs\n", bt.SizeGB, bt.Code, bt.Dirs)
	}
	if r.Totals.Errors > 0 {
		fmt.Fprintf(w, "%s\n", dim(fmt.Sprintf("%d dirs had walk errors (see sizePartial entries)", r.Totals.Errors)))
	}
	if r.Excluded > 0 {
		fmt.Fprintf(w, "%s\n", dim(fmt.Sprintf("%d dirs below --min-gb excluded from this listing (totals count them)", r.Excluded)))
	}
}

func (r *ScanReport) of(v string) []Entry {
	var out []Entry
	for _, e := range r.Entries {
		if e.Verdict == v {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SizeBytes != out[j].SizeBytes {
			return out[i].SizeBytes > out[j].SizeBytes
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func rootPaths(roots []RootSummary) []string {
	out := make([]string, len(roots))
	for i, r := range roots {
		out[i] = r.Path
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n > 3 {
		return "..." + s[len(s)-n+3:]
	}
	return s[:n]
}

// dim marks de-emphasized text. Color policy (NO_COLOR etc.) is the CLI's
// concern; the renderer emits plain markers the CLI can substitute.
func dim(s string) string { return s }
