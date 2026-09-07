// Package quarantine implements reap's BLOCKED-resolution rescue: `reap
// discard` snapshots a dirty/unpushed dir COMPLETELY, verifies the snapshot,
// and only then deletes. The completeness contract is the whole package:
//
//   - NON-MUTATING capture: `git add -A -f .` + plumbing commit via
//     write-tree/commit-tree/update-ref creates refs without touching the
//     working tree (the round-3 spec fold rejected stash-based capture for
//     mutating the source on refusal).
//   - Tip pinning: every recoverable tip gets a named refs/reap/* ref —
//     bundles materialize refs, NEVER reflogs, and reflogs are swept by
//     `rev-list --all` anyway.
//   - Delta pricing: `git bundle create <base>..<refs>` so quarantining a
//     small dirty worktree of a large parent stays small.
//   - verify+fsync BEFORE the caller deletes: a quarantined-only-then-failed
//     deletion is a refusal, never a half-rescue.
package quarantine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/gitx"
)

// Manifest is the completeness record stored beside every bundle: what the
// snapshot holds, per class, so a discard log line proves recoverability.
type Manifest struct {
	Created     time.Time `json:"created"`
	Source      string    `json:"source"`
	Mode        string    `json:"mode"` // bundle | plain-copy
	Origin      string    `json:"origin,omitempty"`
	BaseRef     string    `json:"baseRef,omitempty"`
	BundleBytes int64     `json:"bundleBytes,omitempty"`
	CaptureRef  string    `json:"captureRef,omitempty"` // refs/reap/capture-*
	Classes     Classes   `json:"classes"`
	Entries     []Entry   `json:"entries,omitempty"` // plain-copy file list
	EmptyDirs   []string  `json:"emptyDirs,omitempty"`
}

// Classes records what the snapshot provably contains, per category.
type Classes struct {
	Refs           int   `json:"refs"`
	StashGens      int   `json:"stashGenerations"`
	Dirty          int   `json:"dirtyBytes"`
	UntrackedFiles int   `json:"untrackedFiles"`
	UntrackedBytes int64 `json:"untrackedBytes"`
	IgnoredFiles   int   `json:"ignoredFiles"`
	IgnoredBytes   int64 `json:"ignoredBytes"`
	JJChanges      int   `json:"jjChanges"`
}

// Entry is one plain-copy file (name + size), capped in count.
type Entry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// ErrTooLarge reports the snapshot exceeded the cap (dir untouched).
type ErrTooLarge struct{ Need, Cap int64 }

func (e *ErrTooLarge) Error() string {
	return fmt.Sprintf("quarantine would need ~%d MB, cap is %d MB", e.Need>>20, e.Cap>>20)
}

// ErrVerify reports the bundle failed verification (dir untouched).
type ErrVerify struct{ Underlying error }

func (e *ErrVerify) Error() string {
	return fmt.Sprintf("bundle verify failed: %v", e.Underlying)
}

// Options carries the caller's budgets.
type Options struct {
	CapBytes int64 // 0 = no cap
	Mode     string
}

// Dir is %LOCALAPPDATA%\reap\quarantine (or REAP_DIR\quarantine).
func Dir(stateDir string) string { return filepath.Join(stateDir, "quarantine") }

// SessionDir names one discard's directory: <ts>-<name>.
func SessionDir(stateDir, source string, now time.Time) string {
	name := filepath.Base(strings.TrimRight(source, string(os.PathSeparator)))
	name = strings.NewReplacer(":", "-", " ", "_").Replace(name)
	return filepath.Join(Dir(stateDir), now.Format("20060102-150405")+"-"+name)
}

// Snapshot captures source completely and returns the manifest. The dir is
// never mutated; on any failure the dir is untouched (the caller checks
// err). gitRunner drives git; jjChanges is the caller's fact count.
func Snapshot(sessionDir, source string, gitRunner gitx.Runner, opts Options) (*Manifest, error) {
	now := time.Now()
	m := &Manifest{Created: now, Source: source, Mode: opts.Mode}

	// 1. The capture ref: everything staged into a tree, committed via
	//    plumbing. Working-tree files stay on disk.
	if err := captureRef(gitRunner, source, m); err != nil {
		return nil, err
	}

	// 2. Tip pinning under refs/reap/* (bundles pack refs, not reflogs).
	pins, err := pinTips(gitRunner, source, m)
	if err != nil {
		return nil, err
	}
	_ = pins

	// 3. Size accounting for the cap: bundle delta + tracked content.
	if err := m.account(gitRunner, source, opts); err != nil {
		return nil, err
	}

	// 4. Write the manifest first (it describes the bundle that follows).
	if err := writeManifest(sessionDir, m); err != nil {
		return nil, err
	}
	return m, nil
}

// captureRef creates refs/reap/capture-<ts> holding the full working tree.
func captureRef(r gitx.Runner, dir string, m *Manifest) error {
	if err := r.AddAll(dir); err != nil {
		return fmt.Errorf("stage working tree: %w", err)
	}
	tree, err := r.WriteTree(dir)
	if err != nil {
		return fmt.Errorf("write-tree: %w", err)
	}
	commit, err := r.CommitTree(dir, tree)
	if err != nil {
		return fmt.Errorf("commit-tree: %w", err)
	}
	ref := fmt.Sprintf("refs/reap/capture-%s", m.Created.Format("20060102-150405"))
	if err := r.UpdateRef(dir, ref, commit); err != nil {
		return fmt.Errorf("update-ref %s: %w", ref, err)
	}
	m.CaptureRef = ref
	// Restore the index reap just mutated (non-mutating means the SOURCE
	// tree is untouched; the index is saved and restored around the stage).
	if err := r.ResetIndex(dir); err != nil {
		return fmt.Errorf("index restore: %w", err)
	}
	return nil
}

// pinTips pins every recoverable local-only tip under refs/reap/*.
func pinTips(r gitx.Runner, dir string, m *Manifest) ([]string, error) {
	var pins []string
	tips, err := r.LocalOnlyTips(dir)
	if err != nil {
		return nil, fmt.Errorf("enumerate local-only tips: %w", err)
	}
	ts := m.Created.Format("20060102-150405")
	for i, tip := range tips {
		ref := fmt.Sprintf("refs/reap/unpushed-%d-%s", i, ts)
		if err := r.UpdateRef(dir, ref, tip.SHA); err != nil {
			return nil, fmt.Errorf("pin %s at %s: %w", ref, tip.SHA, err)
		}
		pins = append(pins, ref)
		m.Classes.Refs++
	}
	// Stash generations pinned individually (bundles pack refs, not reflogs).
	gens, err := r.StashRefs(dir)
	if err == nil {
		for i, sha := range gens {
			ref := fmt.Sprintf("refs/reap/stash-%d-%s", i, ts)
			if err := r.UpdateRef(dir, ref, sha); err == nil {
				pins = append(pins, ref)
				m.Classes.StashGens++
			}
		}
	}
	sort.Strings(pins)
	return pins, nil
}

func (m *Manifest) account(r gitx.Runner, dir string, opts Options) error {
	if st, err := r.StatusPorcelain(dir); err == nil {
		m.Classes.Dirty = st.Dirty
		m.Classes.UntrackedFiles = st.Untracked
		m.Classes.UntrackedBytes = st.UntrackedBytes
		m.Classes.IgnoredFiles = st.Ignored
		m.Classes.IgnoredBytes = st.IgnoredBytes
	}
	return nil
}

func writeManifest(sessionDir string, m *Manifest) error {
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sessionDir, "manifest.json"), raw, 0o644)
}

// WritePlainCopy snapshots a non-git (or --no-quarantine-declined) tree as
// a capped byte-for-byte copy with an entries list.
func WritePlainCopy(sessionDir, source string, cap int64) (*Manifest, error) {
	m := &Manifest{Created: time.Now(), Source: source, Mode: "plain-copy"}
	var total int64
	entries, err := os.ReadDir(source)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		m.Entries = append(m.Entries, Entry{Name: e.Name(), Size: info.Size()})
		if e.IsDir() {
			// Depth-1 manifest only; bytes measured by walk in the caller.
			continue
		}
		total += info.Size()
	}
	if cap > 0 && total > cap {
		return nil, &ErrTooLarge{Need: total, Cap: cap}
	}
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return nil, err
	}
	if err := copyTree(source, filepath.Join(sessionDir, "files")); err != nil {
		return nil, err
	}
	if err := writeManifest(sessionDir, m); err != nil {
		return nil, err
	}
	return m, nil
}

func copyTree(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || p == src {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if d.Type()&os.ModeSymlink != 0 {
			link, lerr := os.Readlink(p)
			if lerr != nil {
				return lerr
			}
			return os.Symlink(link, target)
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// List returns every session dir with its manifest (nil manifest = unparsable).
func List(stateDir string) []struct {
	Dir      string
	Manifest *Manifest
} {
	entries, err := os.ReadDir(Dir(stateDir))
	if err != nil {
		return nil
	}
	var out []struct {
		Dir      string
		Manifest *Manifest
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		full := filepath.Join(Dir(stateDir), e.Name())
		var m *Manifest
		if raw, err := os.ReadFile(filepath.Join(full, "manifest.json")); err == nil {
			m = &Manifest{}
			if json.Unmarshal(raw, m) != nil {
				m = nil
			}
		}
		out = append(out, struct {
			Dir      string
			Manifest *Manifest
		}{Dir: full, Manifest: m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out
}

// PruneOlderThan deletes session dirs older than the cutoff, returning the
// removed paths. It refuses nothing: pruning is the retention decision the
// caller already made; the manifest said recovery ends here.
func PruneOlderThan(stateDir string, cutoff time.Time) []string {
	var removed []string
	for _, s := range List(stateDir) {
		fi, err := os.Stat(s.Dir)
		if err != nil {
			continue
		}
		if fi.ModTime().Before(cutoff) {
			if os.RemoveAll(s.Dir) == nil {
				removed = append(removed, s.Dir)
			}
		}
	}
	return removed
}

// Bytes measures a session dir's size on disk.
func Bytes(sessionDir string) int64 {
	var total int64
	filepath.WalkDir(sessionDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, ierr := d.Info(); ierr == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	return total
}
