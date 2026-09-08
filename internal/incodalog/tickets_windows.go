//go:build windows

package incodalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/deblasis/reap/internal/lockfile"
)

// TicketLive probes whether an incoda ticket file still holds its lock,
// using lockfile's port of incoda's own protocol (an exclusive byte at
// offset 2^62): TryLock succeeding means no holder (free); ERROR_LOCK_
// VIOLATION means a live incoda holds it. A ticket that cannot be opened
// or probed is treated as LIVE (absent evidence must never read as
// inactive). The open is EXISTING-ONLY: OPEN_ALWAYS would re-create a
// ticket deleted between the ReadDir and here, writing into incoda state
// reap promises never to touch.
func TicketLive(path string) bool {
	f, err := openTicketExisting(path)
	if err != nil {
		return true // cannot open (incl. vanished): treat as live
	}
	defer f.Close()
	held, err := f.TryLock()
	if err != nil {
		return true // probe error: treat as live
	}
	if held {
		f.Unlock() // we acquired it: nothing holds it; release and report free
		return false
	}
	return true // conflict: a live holder
}

// openTicketExisting opens a ticket without creating it (share-delete,
// GENERIC_READ|GENERIC_WRITE as LockFileEx requires - content untouched:
// no TRUNCATE, no attribute writes; live-proven against real held tickets).
func openTicketExisting(path string) (*lockfile.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return lockfile.NewFile(uintptr(h), path), nil
}

// ticketDir parses a ticket body into the dir it names. REAL incoda
// tickets are single-line JSON with a cwd field (live-verified on this
// machine: pid/queue/slots/arrival/acquire/command/reason/owner/hostname/
// cwd); the dir=-line form is kept as a forward-compat fallback.
func ticketDir(body []byte) string {
	var t struct {
		Cwd string `json:"cwd"`
		Dir string `json:"dir"`
	}
	if err := json.Unmarshal(body, &t); err == nil {
		if t.Cwd != "" {
			return strings.TrimSpace(t.Cwd)
		}
		if t.Dir != "" {
			return strings.TrimSpace(t.Dir)
		}
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "dir=") {
			return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "dir="), "\r"))
		}
	}
	return ""
}

// ProbeRail walks every queue's ticket files once and returns the rail's
// health: each HELD ticket's dir plus the failure names. ANY enumeration
// failure sets Unknown: the queues dir existing but not listing, ONE queue
// dir whose tickets cannot be enumerated, or a ticket that is PERSISTENTLY
// held with a body that cannot be read or parsed into a dir. Transitions
// are distinguished from failures (the R5 gate-red lesson: a machine-wide
// sentinel on every routine lane transition reds the destructive suite and
// skips all deletions under normal churn): incoda DELETES tickets at
// release (and actively reaps foreign ones), so a ticket that vanishes
// mid-sweep is a RELEASED one - inert; Enroll takes the lock BEFORE
// writing the body and the body is REWRITTEN at acquire, so an empty or
// torn body on a held ticket gets a liveness re-probe and one re-read
// before it counts as unknown. Absent evidence must never read as
// inactive; equally, a completed release must not read as unknown.
func ProbeRail() RailHealth {
	var h RailHealth
	qd := filepath.Join(StateDir(), "queues")
	queues, err := os.ReadDir(qd)
	if err != nil {
		// Existed but will not list: wholly unknown (the never-existed case
		// degrades silently - there is no rail to be blind about).
		h.Unknown = stateDirExisted()
		if h.Unknown {
			h.UnreadableQueues = append(h.UnreadableQueues, qd)
		}
		return h
	}
	for _, q := range queues {
		if !q.IsDir() {
			continue
		}
		tickets, terr := os.ReadDir(filepath.Join(qd, q.Name()))
		if terr != nil {
			// The queue just listed but its tickets cannot be enumerated:
			// that queue's liveness is unknown (the sentinel one level down).
			h.Unknown = true
			h.UnreadableQueues = append(h.UnreadableQueues, filepath.Join(qd, q.Name()))
			continue
		}
		for _, tf := range tickets {
			if tf.IsDir() || !strings.HasSuffix(tf.Name(), ".ticket") {
				continue
			}
			full := filepath.Join(qd, q.Name(), tf.Name())
			if !TicketLive(full) {
				continue // stale file: no holder
			}
			body, berr := os.ReadFile(full)
			if berr != nil {
				if os.IsNotExist(berr) {
					continue // vanished mid-sweep: RELEASED (incoda deletes at release)
				}
				if !TicketLive(full) {
					continue // released between the probe and the read
				}
				h.Unknown = true // persistently held, unreadable body
				h.UnattributableLive = append(h.UnattributableLive, full)
				continue
			}
			d := ticketDir(body)
			if d == "" {
				// Held with an empty/torn body: the enroll/acquire rewrite
				// window. Re-probe liveness, then re-read once - only a
				// PERSISTENTLY held-and-unattributable ticket is unknown.
				if !TicketLive(full) {
					continue // released mid-sweep
				}
				body2, err2 := os.ReadFile(full)
				if os.IsNotExist(err2) {
					continue // vanished: released
				}
				d2 := ""
				if err2 == nil {
					d2 = ticketDir(body2)
				}
				if d2 != "" {
					h.Dirs = append(h.Dirs, d2)
					continue
				}
				if !TicketLive(full) {
					continue // released between the re-probe and the re-read
				}
				h.Unknown = true
				h.UnattributableLive = append(h.UnattributableLive, full)
				continue
			}
			h.Dirs = append(h.Dirs, d)
		}
	}
	return h
}

// LiveTicketDirs returns every held ticket's dir= (the pure-ticket half of
// the ACTIVE rail: a ticket the best-effort log never recorded is still
// the authoritative liveness signal). Any enumeration unknown collapses to
// a single "" sentinel entry (live-or-unknown at the enumeration level:
// silent-empty is the unsafe direction - the caller treats the sentinel as
// unknown-live).
func LiveTicketDirs() []string {
	h := ProbeRail()
	if h.Unknown {
		h.Dirs = append(h.Dirs, "")
	}
	return h.Dirs
}

// LiveTicketHit is the containment probe WITH ITS CAUSE: unknown=true
// means the rail could not enumerate (the caller must refuse the SAFE
// direction AND say why - 'enumeration incomplete', not 'a ticket sits
// here': the remedies differ, fix-the-rail vs wait-for-the-job). A hit
// without unknown means a held ticket names a dir at or under root.
func LiveTicketHit(root string) (hit, unknown bool) {
	h := ProbeRail()
	if h.Unknown {
		return true, true
	}
	rootNorm := strings.ToLower(filepath.Clean(root))
	for _, d := range h.Dirs {
		dn := strings.ToLower(filepath.Clean(d))
		if dn == rootNorm || strings.HasPrefix(dn, rootNorm+string(os.PathSeparator)) {
			return true, false
		}
	}
	return false, false
}

// LiveTicketsUnder reports whether any live ticket names a dir at or under
// root (the ACTIVE rail's probe). Stale ticket FILES (no holder) are
// inert; only a held lock whose ticket body's cwd sits at/under root
// counts. Any enumeration unknown reads LIVE-OR-UNKNOWN for every root
// (absent evidence must never read as inactive).
func LiveTicketsUnder(root string) bool {
	hit, _ := LiveTicketHit(root)
	return hit
}

// stateDirExisted reports whether incoda's queues dir existed but failed to
// list (vs never existing - the genuinely-absent case degrades silently).
func stateDirExisted() bool {
	fi, err := os.Stat(filepath.Join(StateDir(), "queues"))
	return err == nil && fi.IsDir()
}
