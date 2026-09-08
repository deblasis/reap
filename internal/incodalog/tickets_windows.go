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

// LiveTicketDirs returns every held ticket's dir= (the pure-ticket half of
// the ACTIVE rail: a ticket the best-effort log never recorded is still
// the authoritative liveness signal).
func LiveTicketDirs() []string {
	qd := filepath.Join(StateDir(), "queues")
	queues, err := os.ReadDir(qd)
	if err != nil {
		return nil
	}
	var out []string
	for _, q := range queues {
		if !q.IsDir() {
			continue
		}
		tickets, terr := os.ReadDir(filepath.Join(qd, q.Name()))
		if terr != nil {
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
			if body, berr := os.ReadFile(full); berr == nil {
				if d := ticketDir(body); d != "" {
					out = append(out, d)
				}
			}
		}
	}
	return out
}

// LiveTicketsUnder reports whether any live ticket names a dir at or under
// root (the ACTIVE rail's probe). Stale ticket FILES (no holder) are
// inert; only a held lock whose ticket body's cwd sits at/under root
// counts. An UNREADABLE queues dir reads LIVE-OR-UNKNOWN (the per-ticket
// policy hoisted one level: absent evidence must never read as inactive)
// when it plausibly contains the root.
func LiveTicketsUnder(root string) bool {
	qd := filepath.Join(StateDir(), "queues")
	queues, err := os.ReadDir(qd)
	if err != nil {
		// The state dir existed when the run started but cannot be listed:
		// the safe direction (an unreadable live set is not an empty one).
		return stateDirExisted()
	}
	rootNorm := strings.ToLower(filepath.Clean(root))
	for _, q := range queues {
		if !q.IsDir() {
			continue
		}
		tickets, terr := os.ReadDir(filepath.Join(qd, q.Name()))
		if terr != nil {
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
			// Live holder: its dir must sit at/under root.
			if body, berr := os.ReadFile(full); berr == nil {
				if d := ticketDir(body); d != "" {
					dn := strings.ToLower(filepath.Clean(d))
					if dn == rootNorm || strings.HasPrefix(dn, rootNorm+string(os.PathSeparator)) {
						return true
					}
				}
			}
		}
	}
	return false
}

// stateDirExisted reports whether incoda's queues dir existed but failed to
// list (vs never existing - the genuinely-absent case degrades silently).
func stateDirExisted() bool {
	fi, err := os.Stat(filepath.Join(StateDir(), "queues"))
	return err == nil && fi.IsDir()
}
