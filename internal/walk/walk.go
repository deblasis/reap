// Package walk sizes candidate directories and derives lastActivity.
//
// Two properties are load-bearing for the verdict engine:
//
//   - lastActivity is the max file mtime observed DURING the walk, not the
//     directory's own mtime: on NTFS a dir mtime only ticks when direct
//     children are added or removed, so deep writes (a build dropping files in
//     bin/, an agent editing nested files, every git commit) leave it stale,
//     and stale activity is how a live dir verdicts SAFE.
//   - The size cache is sizes-only by construction: MaxMtime is simply not
//     stored, so no code path can serve a cached activity into a verdict. The
//     spec's cardinal rule (SAFE only on fresh evidence) is enforced by the
//     type, not by discipline.
package walk

import (
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// DirInfo is the result of sizing one candidate directory.
type DirInfo struct {
	Path     string
	Root     string
	Bytes    int64
	Files    int64
	MaxMtime time.Time // walk-derived; future mtimes clamped to now
	Clamped  int       // files whose mtime was in the future and got clamped
	Partial  bool      // a walk error occurred; size is a lower bound
	// NestedVCS lists ".git"/".jj" markers found BELOW the root (depth >= 1),
	// relative to the root. Presence of any routes the dir MANUAL
	// nested-repositories in the verdict matrix.
	NestedVCS []string
}

// Entry sizes one directory tree. It never crosses reparse points (junctions,
// symlinks): a junction under the tree can loop, escape to protected paths, or
// double-count OneDrive placeholders, so reparse children are skipped entirely
// rather than followed. now lets tests pin the future-clamp reference.
func Entry(root, path string, now time.Time) DirInfo {
	info := DirInfo{Path: path, Root: root}

	var walkErr error
	err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			// One bad subtree must not abort the scan; it makes the size a
			// lower bound and the verdict MANUAL (sizePartial).
			info.Partial = true
			if p == path {
				return filepath.SkipAll
			}
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rep, rerr := IsReparse(p, d)
		if rerr != nil {
			// Cannot even stat the entry: same treatment as a walk error.
			info.Partial = true
			return nil
		}
		if rep {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			// Depth comes from the rel path, not a counter: the callback runs
			// to completion before children fire, so a counter cannot span a
			// subtree. A VCS marker belongs to the candidate itself when it
			// sits directly under the root (Dir(rel) == ".") and is "nested"
			// anywhere deeper — that distinction is the whole
			// nested-repositories verdict row.
			if rel, rerr := filepath.Rel(path, p); rerr == nil {
				name := d.Name()
				if (name == ".git" || name == ".jj") && filepath.Dir(rel) != "." {
					info.NestedVCS = append(info.NestedVCS, rel)
				}
			}
			return nil
		}
		fi, serr := d.Info()
		if serr != nil {
			info.Partial = true
			return nil
		}
		info.Bytes += fi.Size()
		info.Files++
		mt := fi.ModTime()
		if mt.After(now) {
			// A clock-skewed or copied-from-the-future file must not make a
			// live dir read as never-active (which would age it into SAFE).
			mt = now
			info.Clamped++
		}
		if mt.After(info.MaxMtime) {
			info.MaxMtime = mt
		}
		return nil
	})
	if err != nil && !info.Partial {
		walkErr = err
		_ = walkErr
		info.Partial = true
	}
	sort.Strings(info.NestedVCS)
	return info
}

// Roots walks the immediate children of every root (a root itself is never a
// candidate) with a bounded worker pool. Roots that cannot be listed are
// reported as Partial entries of their own so the caller can say which root
// was unreadable instead of silently scanning less.
func Roots(roots []string, now time.Time, workers int) []DirInfo {
	if workers < 1 {
		workers = 1
	}
	type job struct{ root, dir string }
	var (
		mu   sync.Mutex
		out  []DirInfo
		wg   sync.WaitGroup
		jobs = make(chan job)
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				info := Entry(j.root, j.dir, now)
				mu.Lock()
				out = append(out, info)
				mu.Unlock()
			}
		}()
	}
	for _, root := range roots {
		children, err := os.ReadDir(root)
		if err != nil {
			mu.Lock()
			out = append(out, DirInfo{Path: root, Root: root, Partial: true})
			mu.Unlock()
			continue
		}
		for _, c := range children {
			// A candidate that is itself a reparse point is surfaced, not
			// walked: the verdict matrix gives reparse candidates KEEP, and
			// their size is the link, not the target tree.
			rep, rerr := IsReparse(filepath.Join(root, c.Name()), c)
			if rerr != nil || rep || !c.IsDir() {
				if rerr != nil || rep {
					mu.Lock()
					out = append(out, DirInfo{Path: filepath.Join(root, c.Name()), Root: root, Partial: rerr != nil})
					mu.Unlock()
				}
				continue
			}
			jobs <- job{root: root, dir: filepath.Join(root, c.Name())}
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
