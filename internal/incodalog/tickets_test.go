//go:build windows

package incodalog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	r := records[work]
	if r == nil || !r.Open {
		t.Fatalf("record: %+v", r)
	}
	// The rail's trigger: OPEN + a held ticket.
	if !LiveTicketsUnder(r.Dir) {
		t.Fatal("open record's live ticket not probed live")
	}
}
