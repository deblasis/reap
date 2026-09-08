//go:build windows

package incodalog

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/deblasis/reap/internal/lockfile"
)

// TicketLive probes whether an incoda ticket file still holds its lock,
// using lockfile's port of incoda's own protocol (an exclusive byte at
// offset 2^62): TryLock succeeding means no holder (free); ERROR_LOCK_
// VIOLATION means a live incoda holds it. A ticket that cannot be opened
// or probed is treated as LIVE (absent evidence must never read as
// inactive).
func TicketLive(path string) bool {
	f, err := lockfile.Open(path)
	if err != nil {
		return true // cannot open: treat as live
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

// LiveTicketsUnder reports whether any live ticket names a dir at or under
// root (the ACTIVE rail's probe). Stale ticket FILES (no holder) are
// inert; only a held lock whose ticket body's dir= sits at/under root
// counts.
func LiveTicketsUnder(root string) bool {
	qd := filepath.Join(StateDir(), "queues")
	queues, err := os.ReadDir(qd)
	if err != nil {
		return false
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
				for _, line := range strings.Split(string(body), "\n") {
					if strings.HasPrefix(line, "dir=") {
						d := strings.ToLower(filepath.Clean(strings.TrimSuffix(strings.TrimPrefix(line, "dir="), "\r")))
						if d == rootNorm || strings.HasPrefix(d, rootNorm+string(os.PathSeparator)) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
