//go:build windows

// Package dedupe implements the deletion-set hardlink pass: logical vs
// expected-reclaim bytes, where files sharing a Windows file index
// (hardlinks) WITHIN the set are counted once. The two-number truth the
// spec pins ("freed ~D GB now") is derived from THIS pass, not from
// logical sizes — zig lane caches share bytes across build dirs, and
// deleting both dirs reclaims the content once.
package dedupe

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// key identifies one physical file: volume serial + file index.
type key struct {
	vol, idxLo, idxHi uint32
}

// Counter accumulates the deletion-set pass across paths AS THEY ARE ABOUT
// TO BE DELETED (a post-hoc walk has nothing left to walk). One shared
// identity map gives set semantics: content hardlinked within the set
// counts once.
type Counter struct {
	seen     map[key]struct{}
	max      int
	files    int
	over     bool
	Logical  int64
	Expected int64
}

// NewCounter bounds the pass at maxFiles (0 = default). Crossing the bound
// sets Over: the caller falls back to logical with the skipped caveat.
func NewCounter(maxFiles int) *Counter {
	if maxFiles <= 0 {
		maxFiles = 50000
	}
	return &Counter{seen: map[key]struct{}{}, max: maxFiles}
}

// Add walks one path into the counter.
func (c *Counter) Add(root string) {
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		c.files++
		if c.files > c.max {
			c.over = true
			return filepath.SkipAll
		}
		fi, ferr := d.Info()
		if ferr != nil {
			return nil
		}
		c.Logical += fi.Size()
		if c.sharedUnder(p) {
			// Same physical file already counted in this set.
			return nil
		}
		c.Expected += fi.Size()
		return nil
	})
}

// Over reports whether the file cap was crossed (logical + caveat time).
func (c *Counter) Over() bool { return c.over }

// IndexesAvailable reports whether the filesystem exposes classic file
// indexes for path's volume (ReFS/Dev Drive volumes do not; the pass
// degrades to the logical upper bound there). Round-4 fix: presence in the
// map, never the stored value — the bool-value version was constant-false
// and made every volume "unsupported".
func IndexesAvailable(path string) bool {
	c := Counter{seen: map[key]struct{}{}}
	c.sharedUnder(path)
	return c.sharedUnder(path)
}

// sharedUnder records the file's identity and reports whether the same
// physical file was already seen in this set. A zero file index (some
// filesystems) degrades to always-distinct — the logical upper bound.
func (c *Counter) sharedUnder(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return false
	}
	if info.FileIndexLow == 0 && info.FileIndexHigh == 0 {
		return false
	}
	k := key{vol: info.VolumeSerialNumber, idxLo: info.FileIndexLow, idxHi: info.FileIndexHigh}
	if _, ok := c.seen[k]; ok {
		return true
	}
	c.seen[k] = struct{}{}
	return false
}
