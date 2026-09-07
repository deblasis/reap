package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/ghx"
	"github.com/deblasis/reap/internal/jjx"
	"github.com/deblasis/reap/internal/lockfile"
	"github.com/deblasis/reap/internal/quarantine"
)

// cmdDoctor implements `reap doctor`: the state-of-the-world readout.
func cmdDoctor(args []string, stdout, stderr io.Writer) int {
	stateDir, err := config.StateDir()
	if err != nil {
		fmt.Fprintf(stderr, "reap doctor: %v\n", err)
		return ExitState
	}
	cfg, err := config.Load(stateDir)
	if err != nil {
		fmt.Fprintf(stderr, "reap doctor: %v\n", err)
		return ExitState
	}

	fmt.Fprintf(stdout, "state dir: %s\n", stateDir)
	fmt.Fprintf(stdout, "config: %s (roots below as expanded; elevated contexts resolve %%TEMP%% elsewhere)\n", config.ConfigPath(stateDir))
	for _, r := range config.ExpandRoots(cfg.Roots) {
		marker := ""
		if fi, err := os.Stat(r); err != nil {
			marker = "  (unreadable)"
		} else if !fi.IsDir() {
			marker = "  (not a directory)"
		}
		fmt.Fprintf(stdout, "  root: %s%s\n", r, marker)
	}

	// Lock state.
	lockPath := filepath.Join(stateDir, "apply.lock")
	if l, err := lockfile.Open(lockPath); err == nil {
		free, ferr := l.TryLock()
		l.Close()
		if ferr == nil && !free {
			holder := "(unknown holder)"
			if raw, rerr := os.ReadFile(lockPath); rerr == nil && len(raw) > 0 {
				holder = strings.TrimSpace(string(raw))
			}
			fmt.Fprintf(stdout, "apply.lock: HELD by %s\n", holder)
		} else if ferr == nil {
			fmt.Fprintf(stdout, "apply.lock: free\n")
		}
	}

	// Quarantine readout.
	qTotal, qOldest := quarantineStats(stateDir)
	fmt.Fprintf(stdout, "quarantine: %d MB across sessions, oldest %dd\n", qTotal>>20, qOldest)

	// Ledger.
	ledger := ledgerStats(stateDir)
	fmt.Fprintf(stdout, "reap.log: %d KB, %d line(s), spans %s\n", ledger.bytes>>10, ledger.lines, ledger.span)

	// Tool health.
	ghInstalled, ghAuthed := ghx.Client{Budget: 15 * time.Second}.AuthStatus()
	if ghInstalled {
		if ghAuthed {
			fmt.Fprintf(stdout, "gh: installed and authenticated\n")
		} else {
			fmt.Fprintf(stdout, "gh: installed but NOT authenticated (SAFE silently collapses to near zero; run gh auth login)\n")
		}
	} else {
		fmt.Fprintf(stdout, "gh: not on PATH (open-PR fact unavailable)\n")
	}
	if jjx.Available() {
		fmt.Fprintf(stdout, "jj: installed\n")
	} else {
		fmt.Fprintf(stdout, "jj: not on PATH (jj facts degrade to facts-unavailable)\n")
	}

	// Stray healing.
	healed := 0
	for _, r := range config.ExpandRoots(cfg.Roots) {
		entries, derr := os.ReadDir(r)
		if derr != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".reap-probing") {
				stray := filepath.Join(r, e.Name())
				orig := filepath.Join(r, strings.TrimSuffix(e.Name(), ".reap-probing"))
				if _, oerr := os.Stat(orig); os.IsNotExist(oerr) {
					if os.Rename(stray, orig) == nil {
						healed++
					}
				} else {
					parked := stray + ".reap-orphaned-" + time.Now().Format("150405")
					if os.Rename(stray, parked) == nil {
						healed++
					}
				}
			}
		}
	}
	fmt.Fprintf(stdout, "stray .reap-probing dirs healed: %d\n", healed)
	fmt.Fprintf(stdout, "downgraded dirs last scan: (see reap log envelope lines)\n")

	// Aged index.lock listing.
	for _, r := range config.ExpandRoots(cfg.Roots) {
		entries, derr := os.ReadDir(r)
		if derr != nil {
			continue
		}
		for _, e := range entries {
			g := filepath.Join(r, e.Name(), ".git", "index.lock")
			if fi, gerr := os.Stat(g); gerr == nil && time.Since(fi.ModTime()) > time.Hour {
				fmt.Fprintf(stdout, "aged index.lock: %s (%.0fh old; delete if no git is running)\n", g, time.Since(fi.ModTime()).Hours())
			}
		}
	}
	return ExitOK
}

func quarantineStats(stateDir string) (total int64, oldestDays int) {
	for _, s := range quarantine.List(stateDir) {
		total += quarantine.Bytes(s.Dir)
		if fi, err := os.Stat(s.Dir); err == nil {
			d := int(time.Since(fi.ModTime()).Hours() / 24)
			if d > oldestDays {
				oldestDays = d
			}
		}
	}
	return
}

type ledgerInfo struct {
	bytes int64
	lines int
	span  string
}

func ledgerStats(stateDir string) ledgerInfo {
	var li ledgerInfo
	newest, oldest := time.Time{}, time.Time{}
	files := []string{filepath.Join(stateDir, "reap.log")}
	for i := 1; i <= 5; i++ {
		p := filepath.Join(stateDir, fmt.Sprintf("reap.log.%d", i))
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		}
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		li.bytes += int64(len(raw))
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line == "" {
				continue
			}
			li.lines++
			var probe struct {
				TS string `json:"ts"`
			}
			if json.Unmarshal([]byte(line), &probe) == nil {
				if ts, perr := time.Parse(time.RFC3339Nano, probe.TS); perr == nil {
					if oldest.IsZero() || ts.Before(oldest) {
						oldest = ts
					}
					if newest.IsZero() || ts.After(newest) {
						newest = ts
					}
				}
			}
		}
	}
	if !oldest.IsZero() && !newest.IsZero() {
		li.span = fmt.Sprintf("%s to %s", oldest.Format("2006-01-02"), newest.Format("2006-01-02"))
	} else {
		li.span = "(empty)"
	}
	return li
}
