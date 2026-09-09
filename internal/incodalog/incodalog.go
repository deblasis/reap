// Package incodalog parses incoda's lane.log files (best-effort history,
// never authoritative): append-only JSON-free lines per queue at
// %LOCALAPPDATA%\incoda\queues\<key>\lane.log, shaped
// "2006-01-02 15:04:05 queue=<key> event=<event> pid=<pid> k=v ... cmd=<rest>".
//
// Two generations must parse: the OLD format (no dir=) and the NEW format
// (the proposed incoda PR: dir= always, reason=/owner= when set, %q-quoted,
// dur= on release). Old-format events carry no dir key, so they are COUNTED
// and surfaced as weak - never attributed (release lines carry no cmd=
// either, so there is nothing sound to attribute them by; the interim
// cmd-substring idea the spec originally sketched is unimplementable on the
// real log shape). Malformed lines are skipped, never fatal: Queue.Logf
// swallows write failures on incoda's side, so a torn line is expected.
package incodalog

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/config"
)

// Event is one parsed lane.log line.
type Event struct {
	Queue string
	Time  time.Time
	Type  string // enqueue | acquire | release | reaped | giveup | kill | kill-request | force-release | reenter | config
	PID   int
	Cmd   string
	// New-format attribution fields (empty in old logs).
	Dir    string
	Reason string
	Owner  string
	Dur    time.Duration // release only
	// Weak (old logs): the event carries no dir=, so it is counted and
	// surfaced, never attributed.
	Weak bool
}

// StateDir resolves incoda's state directory: $INCODA_DIR, then the
// platform default (LOCALAPPDATA / Library/Application Support /
// XDG_STATE_HOME). Reimplemented rather than imported: no coupling, and
// reap never writes to incoda state.
func StateDir() string {
	if d := os.Getenv("INCODA_DIR"); d != "" {
		return d
	}
	if ld := os.Getenv("LOCALAPPDATA"); ld != "" {
		return filepath.Join(ld, "incoda")
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		cand := filepath.Join(home, "Library", "Application Support", "incoda")
		if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
			return cand
		}
	}
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "incoda")
	}
	return filepath.Join(home, ".local", "state", "incoda")
}

// Queues lists the queue keys present in incoda's state dir.
func Queues() []string {
	entries, err := os.ReadDir(filepath.Join(StateDir(), "queues"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// terminators are the release-equivalent event types: any of these ends an
// enqueue/acquire cycle (spec: "reaped/giveup/kill/force-release are
// release-equivalent terminators").
func terminator(t string) bool {
	switch t {
	case "release", "reaped", "giveup", "kill", "force-release":
		return true
	}
	return false
}

// Parse parses one lane.log's lines (queue is the queue key; the line's
// own queue= must agree or the line is malformed). Torn/malformed lines
// are skipped silently: the log is best-effort on the writer's side.
func Parse(queue, path string) []Event {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []Event
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if e, ok := parseLine(queue, line); ok {
			out = append(out, e)
		}
	}
	return out
}

// parseLine parses "ts queue=K event=T pid=P k=v ... cmd=<rest>".
// Fields before cmd are whitespace-delimited k=v pairs (pid/slots/rc/
// peak_mem/cpu/owner/dir/reason/dur); cmd takes the REST of the line
// (commands contain spaces and quotes).
func parseLine(queue, line string) (Event, bool) {
	var e Event
	// Timestamp: two tokens (date + time).
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return e, false
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", fields[0]+" "+fields[1], time.Local)
	if err != nil {
		return e, false
	}
	e.Time = ts
	e.Queue = queue
	rest := fields[2:]
	// Quoted values span whitespace tokens ("reason=\"big build\""): rejoin
	// FIRST (a cmd=-containing token inside a quoted span is not a field
	// boundary), then absorb an UNQUOTED owner=/reason= free-text tail
	// ("owner=issue-1002 session (badge)" is three tokens; the k=v cut
	// alone keeps only "issue-1002" - 34 of 544 deployed owner lines carry
	// spaces), then locate the cmd= field among the joined pairs.
	pairs := absorbUnquoted(joinQuoted(rest))
	cmdIdx := -1
	for i, f := range pairs {
		if strings.HasPrefix(f, "cmd=") {
			cmdIdx = i
			break
		}
	}
	kvEnd := len(pairs)
	if cmdIdx >= 0 {
		kvEnd = cmdIdx
	}
	for _, f := range pairs[:kvEnd] {
		k, v, ok := cut(f, "=")
		if !ok {
			continue // stray token: skip, not fatal
		}
		switch k {
		case "queue":
			if v != queue {
				return Event{}, false // cross-queue line in the wrong file
			}
		case "event":
			e.Type = v
		case "pid":
			if n, err := strconv.Atoi(v); err == nil {
				e.PID = n
			}
		case "dir":
			// A SECOND dir= with a different value is malformed (the
			// round-6 guard: an unquoted owner= free tail containing a
			// 'dir=...' token would otherwise mint a spurious pair whose
			// last-wins override misattributes the event to the wrong dir -
			// a false-SAFE-direction channel in the enrichment).
			if e.Dir != "" && e.Dir != unquote(v) {
				return Event{}, false
			}
			e.Dir = unquote(v)
		case "reason":
			e.Reason = unquote(v)
		case "owner":
			e.Owner = unquote(v)
		case "dur":
			if d, err := time.ParseDuration(v); err == nil {
				e.Dur = d
			}
		case "slots", "rc", "peak_mem", "cpu", "exclusive":
			// parsed by consumers when needed; not attribution-relevant
		}
	}
	if cmdIdx >= 0 {
		// Reconstruct the command: everything after the cmd= pair, joined
		// with single spaces (the writer's own quoting preserved).
		e.Cmd = strings.Join(pairs[cmdIdx+1:], " ")
		if k, v, ok := cut(pairs[cmdIdx], "="); ok && k == "cmd" && v != "" {
			// cmd=value glued (no space): prepend the glued value.
			e.Cmd = v + " " + e.Cmd
		}
	}
	if e.Type == "" {
		return e, false
	}
	e.Weak = e.Dir == ""
	return e, true
}

func cut(s, sep string) (string, string, bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// joinQuoted merges token runs that an opening quote spans: the new format
// writes reason="big build" as THREE whitespace tokens ("reason=\"big",
// "build\""); rejoining them restores the k=v pair the writer intended.
// An unclosed quote consumes to the end (best-effort: the log is torn).
func joinQuoted(tokens []string) []string {
	var out []string
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if k, v, ok := cut(t, "="); ok && strings.HasPrefix(v, `"`) && !strings.HasSuffix(v, `"`) {
			// Open quote: consume until it closes.
			joined := t
			for i+1 < len(tokens) && !strings.HasSuffix(tokens[i+1], `"`) {
				i++
				joined += " " + tokens[i]
			}
			if i+1 < len(tokens) {
				i++
				joined += " " + tokens[i]
			}
			_ = k
			out = append(out, joined)
			continue
		}
		out = append(out, t)
	}
	return out
}

// absorbUnquoted merges the free-text tail of an UNQUOTED owner= or
// reason= value with the whitespace tokens that follow it, stopping at the
// next known key or the cmd= field. The writer emits owner= unquoted
// (owner=issue-1002 session (wintty-idle-badge) spans three tokens); the
// plain k=v cut would truncate at the first space, which live-measures to
// 34 of 544 deployed owner lines.
func absorbUnquoted(tokens []string) []string {
	known := map[string]bool{
		"queue": true, "event": true, "pid": true, "dir": true,
		"reason": true, "owner": true, "dur": true, "slots": true,
		"rc": true, "peak_mem": true, "cpu": true, "exclusive": true, "cmd": true,
	}
	var out []string
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		k, v, ok := cut(t, "=")
		if !ok || (k != "owner" && k != "reason") || strings.HasPrefix(v, `"`) {
			out = append(out, t)
			continue // not a free-text value, or quoted (joinQuoted spanned it)
		}
		joined := t
		for i+1 < len(tokens) {
			nk, _, nok := cut(tokens[i+1], "=")
			if nok && known[nk] {
				break
			}
			i++
			joined += " " + tokens[i]
		}
		out = append(out, joined)
	}
	return out
}

// unquote reverses Go's %q quoting for the new-format reason=/owner=
// fields ("a b" -> a b); values that were never quoted pass through.
func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		if u, err := strconv.Unquote(v); err == nil {
			return u
		}
	}
	return v
}

// Record is one dir's attribution digest across all queues: the strongest
// event (max enqueue/acquire/release time), whether a terminator closed
// it, and the new-format fields when present.
type Record struct {
	Dir       string        `json:"dir"`
	LastEvent time.Time     `json:"lastEvent"`
	LastType  string        `json:"lastType"`
	Open      bool          `json:"open"` // enqueue/acquire without a terminator
	Cmd       string        `json:"cmd,omitempty"`
	Reason    string        `json:"reason,omitempty"`
	Owner     string        `json:"owner,omitempty"`
	Dur       time.Duration `json:"dur,omitempty"`
	Queues    []string      `json:"queues"`
}

// Digest joins events per dir: max(enqueue, acquire, release) wins (spec);
// enqueue/acquire without a matching release stays Open (the caller decides
// ACTIVE via the live-ticket probe or the active-hours window). Old-format
// events (no dir=) are EXCLUDED from the digest and counted instead —
// their attribution would be cmd-substring guesswork, reported separately.
// Records are keyed by config.Canonical: the join at the scan side uses
// canonical paths, and a raw-cased dir=C:\... key would miss it (round 4;
// the live rail canonicalizes both sides, the enrichment must too).
func Digest(events []Event) (records map[string]*Record, weakCount int) {
	records = map[string]*Record{}
	for _, ev := range events {
		if ev.Dir == "" {
			if ev.Type == "release" || ev.Type == "enqueue" || ev.Type == "acquire" {
				weakCount++
			}
			continue
		}
		key := config.Canonical(ev.Dir)
		r := records[key]
		if r == nil {
			r = &Record{Dir: ev.Dir}
			records[key] = r
		}
		// !Before, not After: lane.log timestamps are 1-second resolution, and
		// an enqueue+release in the same second left LastType=enqueue and the
		// record reading OPEN forever (append-only order = the later line wins).
		if !ev.Time.Before(r.LastEvent) {
			r.LastEvent = ev.Time
			r.LastType = ev.Type
			r.Cmd, r.Reason, r.Owner, r.Dur = ev.Cmd, ev.Reason, ev.Owner, ev.Dur
		}
		if !contains(r.Queues, ev.Queue) {
			r.Queues = append(r.Queues, ev.Queue)
		}
	}
	for _, r := range records {
		r.Open = !terminator(r.LastType)
	}
	return records, weakCount
}

// Since filters records to those with an event at or after the cutoff.
func Since(records map[string]*Record, cutoff time.Time) map[string]*Record {
	out := map[string]*Record{}
	for k, r := range records {
		if !r.LastEvent.Before(cutoff) {
			out[k] = r
		}
	}
	return out
}

// CoverageShare reports (attributed, total) event counts for doctor's
// dir= coverage readout: the share of enqueue/acquire/release lines
// carrying real dir= attribution.
func CoverageShare(events []Event) (attributed, total int) {
	for _, ev := range events {
		switch ev.Type {
		case "enqueue", "acquire", "release":
			total++
			if ev.Dir != "" {
				attributed++
			}
		}
	}
	return attributed, total
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// ReadAll parses every queue's lane.log under incoda's state dir.
func ReadAll() []Event {
	var out []Event
	for _, q := range Queues() {
		out = append(out, Parse(q, filepath.Join(StateDir(), "queues", q, "lane.log"))...)
	}
	// STABLE: the digest's same-second tie relies on append-only order
	// surviving the sort (an unstable sort can swap equal-second events and
	// resurrect a closed record as OPEN).
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

// String renders a record for the text table.
func (r *Record) String() string {
	state := "closed"
	if r.Open {
		state = "OPEN"
	}
	return fmt.Sprintf("%s  %-7s  %s  %s", r.LastEvent.Format("2006-01-02 15:04"), state, strings.Join(r.Queues, ","), r.Dir)
}
