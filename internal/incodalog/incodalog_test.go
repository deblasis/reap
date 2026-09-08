package incodalog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeLog(t *testing.T, dir, queue, body string) {
	t.Helper()
	qd := filepath.Join(dir, "queues", queue)
	if err := os.MkdirAll(qd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(qd, "lane.log"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Parser goldens: the old format (no dir=), the new format (dir= always,
// reason=/owner= quoted, dur= on release), malformed lines skipped, and
// the multi-word cmd surviving intact.
func TestParseGoldens(t *testing.T) {
	d := t.TempDir()
	writeLog(t, d, "build", "2026-09-07 18:03:05 queue=build event=enqueue pid=451548 slots=5 cmd=sh -c \"cd x && zig build\"\n"+
		"2026-09-07 18:03:05 queue=build event=acquire pid=451548 cmd=sh -c \"cd x && zig build\"\n"+
		"2026-09-07 18:08:31 queue=build event=release pid=451548 rc=0 peak_mem=4.7 GB cpu=6m16s\n"+
		"garbage line without shape\n"+
		"2026-09-07 19:00:00 queue=other event=reenter pid=1\n"+
		"2026-09-07 19:05:00 queue=build event=release pid=99 dir=C:\\wt\\thing reason=\"big build\" owner=agent dur=42m30s cmd=pwsh -File x.ps1\n")

	t.Setenv("INCODA_DIR", d)
	events := ReadAll()
	if len(events) != 4 { // garbage skipped, cross-queue rejected, the rest parsed
		t.Fatalf("event count: %d (%+v)", len(events), events)
	}
	e0 := events[0]
	if e0.Type != "enqueue" || e0.PID != 451548 || e0.Dir != "" || !e0.Weak {
		t.Fatalf("old enqueue: %+v", e0)
	}
	if e0.Cmd != `sh -c "cd x && zig build"` {
		t.Fatalf("cmd mangled: %q", e0.Cmd)
	}
	// The cross-queue line (queue=other in build's file) is rejected.
	for _, e := range events {
		if e.Type == "reenter" {
			t.Fatal("cross-queue line parsed")
		}
	}
	// The new-format release.
	last := events[len(events)-1]
	if last.Dir != `C:\wt\thing` || last.Reason != "big build" || last.Owner != "agent" {
		t.Fatalf("new-format fields: %+v", last)
	}
	if last.Dur != 42*time.Minute+30*time.Second {
		t.Fatalf("dur: %v", last.Dur)
	}
	if last.Weak {
		t.Fatal("dir=-carrying line marked weak")
	}
}

// The adversarial parser shapes: a quoted reason CONTAINING a cmd=-prefixed
// token (the joinQuoted-before-cmd ordering) and a same-second
// enqueue+release (the !Before tie; a closed record must not read OPEN).
func TestParseQuotedCmdInsideReason(t *testing.T) {
	d := t.TempDir()
	writeLog(t, d, "q", `2026-09-07 20:00:00 queue=q event=enqueue pid=1 dir=C:\a reason="run cmd=now please" owner=me cmd=zig build test`)
	t.Setenv("INCODA_DIR", d)
	events := ReadAll()
	if len(events) != 1 {
		t.Fatalf("events: %d", len(events))
	}
	e := events[0]
	if e.Reason != "run cmd=now please" {
		t.Fatalf("reason corrupted: %q", e.Reason)
	}
	if e.Cmd != "zig build test" {
		t.Fatalf("cmd corrupted: %q", e.Cmd)
	}
}

// An UNQUOTED multi-token owner= value spans its whitespace tokens (34 of
// 544 deployed owner lines carry spaces; the plain k=v cut kept only the
// first token) and stops at the next known key or cmd= (round 5).
func TestParseOwnerSpansTokens(t *testing.T) {
	d := t.TempDir()
	writeLog(t, d, "q", `2026-09-07 21:00:00 queue=q event=release pid=7 dir=C:\w reason="nightly" owner=issue-1002 session (wintty-idle-badge) dur=1h cmd=zig build test`)
	t.Setenv("INCODA_DIR", d)
	events := ReadAll()
	if len(events) != 1 {
		t.Fatalf("events: %d", len(events))
	}
	e := events[0]
	if e.Owner != "issue-1002 session (wintty-idle-badge)" {
		t.Fatalf("owner truncated: %q", e.Owner)
	}
	if e.Reason != "nightly" || e.Dur != time.Hour {
		t.Fatalf("neighbors corrupted: %+v", e)
	}
	if e.Cmd != "zig build test" {
		t.Fatalf("cmd corrupted: %q", e.Cmd)
	}
}

func TestDigestSameSecondTie(t *testing.T) {
	ts := time.Now().Truncate(time.Second)
	records, _ := Digest([]Event{
		{Queue: "q", Time: ts, Type: "enqueue", Dir: `C:\a`},
		{Queue: "q", Time: ts, Type: "release", Dir: `C:\a`},
	})
	r := records[`c:\a`] // keys are canonical (lowercased) since round 4
	if r == nil || r.Open {
		t.Fatalf("same-second release lost to the tie: %+v", r)
	}
}

// The digest join: max(enqueue, acquire, release) per dir; open without a
// terminator; old-format events counted weak, not joined.
func TestDigestJoin(t *testing.T) {
	events := []Event{
		{Queue: "b", Time: time.Now().Add(-3 * time.Hour), Type: "enqueue", Dir: `C:\a`, Cmd: "cmd-a"},
		{Queue: "b", Time: time.Now().Add(-2 * time.Hour), Type: "release", Dir: `C:\a`, Dur: time.Hour},
		{Queue: "c", Time: time.Now().Add(-30 * time.Minute), Type: "acquire", Dir: `C:\open`},
		{Queue: "b", Time: time.Now().Add(-1 * time.Hour), Type: "release"}, // old format, no dir
		{Queue: "d", Time: time.Now().Add(-10 * time.Minute), Type: "kill", Dir: `C:\killed`},
	}
	records, weak := Digest(events)
	if weak != 1 {
		t.Fatalf("weak count: %d", weak)
	}
	if len(records) != 3 {
		t.Fatalf("records: %d", len(records))
	}
	a := records[`c:\a`] // canonical (lowercased) keys
	if a.Open || a.LastType != "release" {
		t.Fatalf("closed record: %+v", a)
	}
	o := records[`c:\open`]
	if !o.Open || o.LastType != "acquire" {
		t.Fatalf("open record: %+v", o)
	}
	k := records[`c:\killed`]
	if k.Open { // kill is a release-equivalent terminator
		t.Fatalf("kill not treated as terminator: %+v", k)
	}
}

// Since filters on the event time.
func TestSince(t *testing.T) {
	now := time.Now()
	records := map[string]*Record{
		`C:\old`:  {LastEvent: now.Add(-48 * time.Hour)},
		`C:\new`:  {LastEvent: now.Add(-1 * time.Hour)},
	}
	out := Since(records, now.Add(-24*time.Hour))
	if _, ok := out[`C:\old`]; ok {
		t.Fatal("old record survived the cutoff")
	}
	if _, ok := out[`C:\new`]; !ok {
		t.Fatal("new record filtered out")
	}
}

// CoverageShare: the doctor readout's numerator/denominator.
func TestCoverageShare(t *testing.T) {
	events := []Event{
		{Type: "enqueue", Dir: "x"},
		{Type: "acquire", Dir: "x"},
		{Type: "release"},               // old
		{Type: "config"},                // not counted
		{Type: "reenter"},               // not counted
		{Type: "release", Dir: "y"},     // new
	}
	a, tot := CoverageShare(events)
	if a != 3 || tot != 4 {
		t.Fatalf("coverage: %d/%d", a, tot)
	}
}
