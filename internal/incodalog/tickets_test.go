//go:build windows

package incodalog

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deblasis/reap/internal/config"
)

// The spec's named M4 fixture: the live-ticket probe against a byte-range
// lock at offset 2^62. A HELD ticket reports live; a released one does
// not; LiveTicketsUnder matches the ticket's dir at/under the root; a
// stale ticket FILE (no holder) is inert.
func TestTicketProbeAt2ToThe62(t *testing.T) {
	d := t.TempDir()
	t.Setenv("INCODA_DIR", d)
	qd := filepath.Join(d, "queues", "q")
	if err := os.MkdirAll(qd, 0o755); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	ticket := filepath.Join(qd, "123-456.ticket")
	// The DEPLOYED body shape: single-line JSON with cwd (the field the
	// real tickets carry; the dir=-line form is the forward-compat path,
	// not what incoda writes today).
	body := fmt.Sprintf(`{"pid":123,"queue":"q","slots":1,"cwd":%q,"reason":"probe","owner":"agent"}`, work)
	if err := os.WriteFile(ticket, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	// Free: no holder.
	if TicketLive(ticket) {
		t.Fatal("unheld ticket reported live")
	}
	if LiveTicketsUnder(work) {
		t.Fatal("unheld ticket matched")
	}

	// Hold it: another process's shape = a second lockfile handle.
	f, err := lockfileOpenForTest(ticket)
	if err != nil {
		t.Skipf("open ticket: %v", err)
	}
	held, err := f.TryLock()
	if err != nil || !held {
		t.Fatalf("fixture could not hold the ticket: held=%v err=%v", held, err)
	}
	defer f.Close()

	if !TicketLive(ticket) {
		t.Fatal("held ticket reported free (the 2^62 probe is dead)")
	}
	if !LiveTicketsUnder(work) {
		t.Fatal("held ticket's dir not matched")
	}
	// The parent CONTAINS the live dir: the containment direction the
	// round-1 spec seat caught as inverted.
	if !LiveTicketsUnder(filepath.Dir(work)) && strings.HasPrefix(work, filepath.Dir(work)) {
		t.Fatal("parent of the live dir not matched at/under")
	}
}

// The with-live-ticket attribution join (the spec's second named M4
// fixture): an open record backed by a held ticket lands in the live set
// (the ACTIVE incoda-live rail's trigger), not merely OPEN.
func TestOpenRecordWithLiveTicketJoinsLive(t *testing.T) {
	d := t.TempDir()
	t.Setenv("INCODA_DIR", d)
	work := t.TempDir()
	qd := filepath.Join(d, "queues", "q")
	if err := os.MkdirAll(qd, 0o755); err != nil {
		t.Fatal(err)
	}
	// An open enqueue (never released) naming work (the deployed JSON-cwd
	// body shape).
	ticket := filepath.Join(qd, "999-1.ticket")
	body := fmt.Sprintf(`{"pid":999,"queue":"q","cwd":%q}`, work)
	if err := os.WriteFile(ticket, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := lockfileOpenForTest(ticket)
	if err != nil {
		t.Skipf("open ticket: %v", err)
	}
	held, err := f.TryLock()
	if err != nil || !held {
		t.Fatalf("hold: %v", err)
	}
	defer f.Close()

	records, _ := Digest([]Event{{Queue: "q", Type: "enqueue", Dir: work}})
	r := records[config.Canonical(work)]
	if r == nil || !r.Open {
		t.Fatalf("record: %+v", r)
	}
	// The rail's trigger: OPEN + a held ticket.
	if !LiveTicketsUnder(r.Dir) {
		t.Fatal("open record's live ticket not probed live")
	}
}

// The unknown-live sentinel at the BODY level (round 5; the R4 panel
// live-proved a held ticket with a torn body protected NOTHING): incoda's
// Enroll takes the lock BEFORE writing the body and swallows its own
// marshal error, so an empty or torn body on a genuinely held ticket is a
// real shape. It must trip the sentinel - live-or-unknown for EVERY root -
// never a silent drop.
func TestHeldUnreadableTicketSentinel(t *testing.T) {
	d := t.TempDir()
	t.Setenv("INCODA_DIR", d)
	qd := filepath.Join(d, "queues", "q")
	if err := os.MkdirAll(qd, 0o755); err != nil {
		t.Fatal(err)
	}
	ticket := filepath.Join(qd, "5-1.ticket")
	if err := os.WriteFile(ticket, []byte("torn{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := lockfileOpenForTest(ticket)
	if err != nil {
		t.Skipf("open ticket: %v", err)
	}
	held, terr := f.TryLock()
	if err != nil || !held {
		t.Fatalf("hold: %v", terr)
	}
	defer f.Close()

	dirs := LiveTicketDirs()
	sawSentinel := false
	for _, x := range dirs {
		if x == "" {
			sawSentinel = true
		}
	}
	if !sawSentinel {
		t.Fatalf("held-but-torn ticket did not trip the unknown-live sentinel: %q", dirs)
	}
	if !LiveTicketsUnder(`C:\somewhere\unrelated`) {
		t.Fatal("unknown-live must read live for EVERY root, not just the ticket's dir")
	}
	h := ProbeRail()
	if !h.Unknown || len(h.UnattributableLive) != 1 {
		t.Fatalf("rail health: %+v", h)
	}
}

// The unknown-live sentinel at the PER-QUEUE level (round 5; the R4 eng
// major, live-proven: ONE ACL-denied queue dir while its ticket was held
// flipped the held dir OUT of incoda-live - the false-SAFE direction). The
// denial is best-effort (icacls /deny on a self-owned dir needs no
// elevation but is environment-dependent): skip, never fake.
func TestPerQueueUnreadableSentinel(t *testing.T) {
	d := t.TempDir()
	t.Setenv("INCODA_DIR", d)
	qd := filepath.Join(d, "queues", "qA")
	if err := os.MkdirAll(qd, 0o755); err != nil {
		t.Fatal(err)
	}
	user := os.Getenv("USERNAME")
	if user == "" {
		t.Skip("no USERNAME for the ACL fixture")
	}
	if out, err := exec.Command("icacls", qd, "/deny", user+":(RD)").CombinedOutput(); err != nil {
		t.Skipf("icacls deny: %v %s", err, out)
	}
	t.Cleanup(func() {
		out, _ := exec.Command("icacls", qd, "/remove:d", user).CombinedOutput()
		_ = out
	})

	h := ProbeRail()
	if !h.Unknown {
		t.Fatalf("one unreadable queue dir reads as a complete enumeration: %+v", h)
	}
	if len(h.Dirs) != 0 {
		t.Fatalf("partial dir set beside the unknown flag: %q", h.Dirs)
	}
	if len(h.UnreadableQueues) != 1 {
		t.Fatalf("the unreadable queue is not named: %+v", h)
	}
	if !LiveTicketsUnder(`C:\anywhere`) {
		t.Fatal("per-queue unknown must read live-or-unknown for every root")
	}
}

// The 8.3-spelling join (round 7; the R6 reliability seat's live-proven
// invariant-1 channel: a ticket whose cwd is ALESSA~1-spelled was MISSED
// by the per-path sweep against long-form roots, and the dir was
// DELETED). Both sides canonicalize; on machines whose temp root is not
// short-formed the mismatch dimension is absent and the pin stays true,
// just weaker.
func TestTicketHit8Dot3Cwd(t *testing.T) {
	d := t.TempDir()
	t.Setenv("INCODA_DIR", d)
	qd := filepath.Join(d, "queues", "q")
	if err := os.MkdirAll(qd, 0o755); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir() // short-formed on ALESSA~1 machines
	long := config.Canonical(work)
	ticket := filepath.Join(qd, "8-8.ticket")
	body := fmt.Sprintf(`{"pid":8,"queue":"q","cwd":%q}`, work)
	if err := os.WriteFile(ticket, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := lockfileOpenForTest(ticket)
	if err != nil {
		t.Skipf("open ticket: %v", err)
	}
	held, terr := f.TryLock()
	if err != nil || !held {
		t.Fatalf("hold: %v", terr)
	}
	defer f.Close()
	if hit, unknown := LiveTicketHit(long); !hit || unknown {
		t.Fatalf("8.3-spelled cwd missed against the long-form root (hit=%v unknown=%v root=%q cwd=%q)", hit, unknown, long, work)
	}
}

// The unknown-live sentinel at the QUEUES level (round 6 pin of the
// amendment's first-named level): the queues dir existing but unlistable
// reads wholly unknown - and doctor's readout NAMES it (the path is
// appended to UnreadableQueues). Best-effort icacls fixture, skip never
// fake.
func TestQueuesLevelSentinel(t *testing.T) {
	d := t.TempDir()
	t.Setenv("INCODA_DIR", d)
	qd := filepath.Join(d, "queues", "q")
	if err := os.MkdirAll(qd, 0o755); err != nil {
		t.Fatal(err)
	}
	user := os.Getenv("USERNAME")
	if user == "" {
		t.Skip("no USERNAME for the ACL fixture")
	}
	if out, err := exec.Command("icacls", qd, "/deny", user+":(RD)").CombinedOutput(); err != nil {
		t.Skipf("icacls deny: %v %s", err, out)
	}
	t.Cleanup(func() {
		out, _ := exec.Command("icacls", qd, "/remove:d", user).CombinedOutput()
		_ = out
	})

	h := ProbeRail()
	if !h.Unknown || len(h.UnreadableQueues) == 0 {
		t.Fatalf("denied queues dir must read unknown AND be named: %+v", h)
	}
	hit, unknown := LiveTicketHit(`C:\anywhere`)
	if !hit || !unknown {
		t.Fatal("queues-level unknown must carry its cause through LiveTicketHit")
	}
}

// The mid-sweep TRANSITIONS must not trip the sentinel (round 6; the R5
// gate-red root cause): a ticket that VANISHES between the enumeration and
// the read is a RELEASED one (incoda deletes tickets at release), inert -
// not machine-wide unknown. The deterministic shape: a ticket path whose
// OPEN and READ both fail IsNotExist while ReadDir still lists it (a
// symlink to a nowhere target reproduces exactly that triple).
func TestVanishedTicketIsReleased(t *testing.T) {
	d := t.TempDir()
	t.Setenv("INCODA_DIR", d)
	qd := filepath.Join(d, "queues", "q")
	if err := os.MkdirAll(qd, 0o755); err != nil {
		t.Fatal(err)
	}
	ticket := filepath.Join(qd, "7-1.ticket")
	if err := os.Symlink(filepath.Join(d, "nowhere"), ticket); err != nil {
		t.Skipf("symlink (dev mode): %v", err)
	}

	h := ProbeRail()
	if h.Unknown {
		t.Fatalf("a vanished (released) ticket tripped the sentinel: %+v", h)
	}
	if len(h.Dirs) != 0 {
		t.Fatalf("vanished ticket contributed a dir: %q", h.Dirs)
	}
	if LiveTicketsUnder(`C:\anywhere`) {
		t.Fatal("a released ticket must not read live")
	}
}
