//go:build !windows

// Package dedupe implements the deletion-set hardlink pass (unix: inode
// identity). See dedupe_windows.go for the contract.
package dedupe

import (
	"os"
	"path/filepath"
	"syscall"
)

type key struct {
	dev, ino uint64
}

// Counter accumulates the deletion-set pass; see dedupe_windows.go.
type Counter struct {
	seen     map[key]struct{}
	max      int
	files    int
	over     bool
	Logical  int64
	Expected int64
}

func NewCounter(maxFiles int) *Counter {
	if maxFiles <= 0 {
		maxFiles = 50000
	}
	return &Counter{seen: map[key]struct{}{}, max: maxFiles}
}

// IndexesAvailable reports whether inode identity works on this platform
// (unix: always true).
func IndexesAvailable(path string) bool { return true }

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
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil && st.Ino != 0 {
			k := key{dev: uint64(st.Dev), ino: uint64(st.Ino)}
			if _, dup := c.seen[k]; dup {
				return nil
			}
			c.seen[k] = struct{}{}
		}
		c.Expected += fi.Size()
		return nil
	})
}

func (c *Counter) Over() bool { return c.over }
