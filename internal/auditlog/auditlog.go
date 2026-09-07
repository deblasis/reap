// Package auditlog is reap's write-ahead deletion ledger. The spec's rule:
// an append failure is a hard abort of apply, because the log IS the
// recovery story — a deletion that might not be logged is a deletion that
// must not happen. Every apply/discard session opens and closes an envelope
// with free-space snapshots so doctor can report measured deltas.
package auditlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Line is one reap.log record. Field names are the spec's schema.
type Line struct {
	RunID        string  `json:"runId"`
	TS           string  `json:"ts"`
	Event        string  `json:"event"` // intent | result | skip | envelope
	Path         string  `json:"path,omitempty"`
	Kind         string  `json:"kind,omitempty"`
	SizeBytes    int64   `json:"sizeBytes,omitempty"`
	Verdict      string  `json:"verdict,omitempty"`
	ReasonCode   string  `json:"reasonCode,omitempty"`
	Origin       string  `json:"origin,omitempty"`
	Branch       string  `json:"branch,omitempty"`
	HeadSHA      string  `json:"headSha,omitempty"`
	LastCommitTs string  `json:"lastCommitTs,omitempty"`
	Dirty        int     `json:"dirty,omitempty"`
	Untracked    int     `json:"untracked,omitempty"`
	Stashes      int     `json:"stashes,omitempty"`
	Ignored      int     `json:"ignored,omitempty"`
	ParentRepo   string  `json:"parentRepoPath,omitempty"`
	Mode         string  `json:"mode,omitempty"` // rm | worktree-remove | jj-forget | plain-copy | no-quarantine
	OK           *bool   `json:"ok"`             // null except on result lines
	Residue      string  `json:"residue,omitempty"`
	Quarantine   *string `json:"quarantinePath"` // null when none
	SkipWhy      string  `json:"skipWhy,omitempty"`
	Planned      int     `json:"planned,omitempty"` // envelope fields
	Deleted      int     `json:"deleted,omitempty"`
	Skipped      int     `json:"skipped,omitempty"`
	FreeBefore   uint64  `json:"freeBytesBefore,omitempty"`
	FreeAfter    uint64  `json:"freeBytesAfter,omitempty"`
	Manifest     []byte  `json:"manifest,omitempty"` // capped top-level listing for non-clean deletions
}

// rotationBound: past this the log rotates whole (reap.log.1), envelopes
// intact — rotation never splits a session's story.
const rotationBound = 50 << 20

// Log appends lines under a process-local mutex (cross-process serialization
// is apply.lock's job; this guards the file handle within one run).
type Log struct {
	mu      sync.Mutex
	path    string
	runID   string
	lastLen int64
}

// Open prepares the ledger for a run. runID stamps every line.
func Open(stateDir, runID string) (*Log, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, "reap.log")
	fi, err := os.Stat(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	l := &Log{path: path, runID: runID}
	if fi != nil {
		l.lastLen = fi.Size()
	}
	return l, nil
}

// Append writes one line. An error here is the hard-abort signal.
func (l *Log) Append(line Line) error {
	line.RunID = l.runID
	line.TS = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(line)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// The handle is closed BEFORE rotation: Windows refuses to rename a file
	// with an open handle, and rotation runs on the same call that crossed
	// the bound.
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("audit append failed (apply must abort): %w", err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("audit append failed (apply must abort): %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("audit append failed (apply must abort): %w", err)
	}
	return l.rotateIfNeeded()
}

func (l *Log) rotateIfNeeded() error {
	fi, err := os.Stat(l.path)
	if err != nil {
		return err
	}
	if fi.Size() < rotationBound {
		return nil
	}
	// Chained rotation: reap.log.1 -> .2 -> ... (bounded at maxGenerations);
	// `reap log` reads all rotations oldest-first per the spec, so history
	// stays multi-generation rather than a single overwritten slot.
	for i := maxGenerations; i >= 2; i-- {
		_ = os.Rename(l.path+"."+fmt.Sprint(i-1), l.path+"."+fmt.Sprint(i))
	}
	_ = os.Rename(l.path, l.path+".1")
	return nil
}

// maxGenerations bounds the rotation chain: reap.log + .1..N. History is
// bounded but multi-generation (the ledger is the recovery story).
const maxGenerations = 5

// NewRunID mints a readable run identifier.
func NewRunID() string {
	return fmt.Sprintf("reap-%s", time.Now().UTC().Format("20060102-150405.000000000"))
}

// FreeBytes reports free space on the volume holding path (0 on error: the
// envelope fields are diagnostics, not gates - the preflight floors use
// their own checked reads).
func FreeBytes(path string) uint64 {
	return diskFree(path)
}
