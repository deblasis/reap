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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	// IsReparse marks a candidate that is itself a junction/symlink: Roots
	// surfaces it WITHOUT walking it, so every other field is the zero value
	// and the verdict must be KEEP, never a verdict computed through the
	// link (a junction into a clean repo would otherwise harvest the
	// target's facts and reach SAFE on evidence about a different path).
	IsReparse bool
	// NestedVCS lists ".git"/".jj" markers found BELOW the root (depth >= 1),
	// relative to the root  -  including submodule .git FILES, which porcelain
	// hides behind ignore=dirty. Presence of any routes the dir MANUAL
	// nested-repositories in the verdict matrix.
	NestedVCS []string
}

// cappedManifestBytes bounds the top-level manifest written into audit
// lines for non-clean deletions: proof of what was there, not a copy.
const cappedManifestBytes = 64 << 10

// CappedManifest lists a directory's top-level entries (name + size, dir
// marked) as JSON, capped: the audit line's "gone is never contents
// unknown" contract without unbounded ledger growth.
func CappedManifest(path string) []byte {
	entries, err := os.ReadDir(longPathLocal(path))
	if err != nil {
		return []byte(`{"error":"unreadable"}`)
	}
	var sb strings.Builder
	sb.WriteString(`{"entries":[`)
	first := true
	for _, e := range entries {
		if !first {
			sb.WriteString(",")
		}
		first = false
		size := int64(0)
		if fi, err := e.Info(); err == nil && !e.IsDir() {
			size = fi.Size()
		}
		name := strings.ReplaceAll(e.Name(), `"`, `\"`)
		kind := "file"
		if e.IsDir() {
			kind = "dir"
		}
		fmt.Fprintf(&sb, `{"name":"%s","kind":"%s","size":%d}`, name, kind, size)
		if sb.Len() > cappedManifestBytes {
			sb.WriteString(`,{"truncated":true}`)
			break
		}
	}
	sb.WriteString(`]}`)
	return []byte(sb.String())
}

func longPathLocal(p string) string { return p }

// Entry sizes one directory tree. It never crosses reparse points (junctions,
// symlinks): a junction under the tree can loop, escape to protected paths, or
// double-count OneDrive placeholders, so reparse children are skipped entirely
// rather than followed. now lets tests pin the future-clamp reference.
func Entry(root, path string, now time.Time) DirInfo {
	info := DirInfo{Path: path, Root: root}

	// An empty tree has no file mtimes; the dir's own mtime is its activity
	// (otherwise a freshly created empty scratch verdicts as 106751 days
	// idle, which is absurd and unsafe). Clamped like any file mtime.
	if fi, err := os.Stat(path); err == nil {
		mt := fi.ModTime()
		if mt.After(now) {
			mt = now
			info.Clamped++
		}
		info.MaxMtime = mt
	}

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
			// anywhere deeper  -  that distinction is the whole
			// nested-repositories verdict row.
			if rel, rerr := filepath.Rel(path, p); rerr == nil {
				name := d.Name()
				if (name == ".git" || name == ".jj") && filepath.Dir(rel) != "." {
					info.NestedVCS = append(info.NestedVCS, rel)
				}
			}
			return nil
		}
		// A ".git" FILE at depth >= 1 is a submodule's gitdir pointer: the
		// submodule's own porcelain is invisible to the superproject (worse
		// behind ignore=dirty), so this marker is the only signal the walk
		// gets. The candidate's own linked .git (depth 0) is not nested.
		if rel, rerr := filepath.Rel(path, p); rerr == nil && d.Name() == ".git" && filepath.Dir(rel) != "." {
			info.NestedVCS = append(info.NestedVCS, rel)
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
			// walked: IsReparse is carried on the DirInfo so the verdict
			// layer can KEEP it without ever reading through the link, and
			// the stat-error flavor stays MANUAL via Partial.
			rep, rerr := IsReparse(filepath.Join(root, c.Name()), c)
			if rerr != nil {
				mu.Lock()
				out = append(out, DirInfo{Path: filepath.Join(root, c.Name()), Root: root, Partial: true})
				mu.Unlock()
				continue
			}
			if rep {
				mu.Lock()
				out = append(out, DirInfo{Path: filepath.Join(root, c.Name()), Root: root, IsReparse: true})
				mu.Unlock()
				continue
			}
			if !c.IsDir() {
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
