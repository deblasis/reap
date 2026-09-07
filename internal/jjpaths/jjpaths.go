// Package jjpaths is the ONE resolver of jj's .jj/repo pointer semantics.
// classify and jjx both need it and had drifted apart re-implementing it  - 
// the drift is exactly how a round-7 fold shipped as a live no-op (the
// pointer names the parent's REPO DIR; `jj workspace list` prints the
// parent ROOT; an exclusion comparing the two never matches).
package jjpaths

import (
	"os"
	"path/filepath"
	"strings"
)

// Layout is the resolved shape of a dir's .jj marker.
type Layout struct {
	// RepoDir is the path the .jj/repo file names verbatim (jj's repo
	// storage; for a colocated root repo this IS <root>/.jj/repo).
	RepoDir string
	// ParentRoot is the WORKSPACE ROOT owning that repo (RepoDir minus the
	// trailing .jj\repo element when colocated, else RepoDir's parent for
	// split layouts). Empty for root repos (the dir is its own parent).
	ParentRoot string
}

// Resolve reads dir/.jj/repo and returns both shapes. ok=false when the
// marker is absent or names the dir itself (a root repo: ParentRoot empty).
// Relative pointer content is resolved against the .jj DIRECTORY (jj 0.44
// semantics: ../../parent/.jj/repo), probing both spellings for tolerance.
func Resolve(dir string) (Layout, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, ".jj", "repo"))
	if err != nil {
		return Layout{}, false
	}
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "." {
		return Layout{}, true // root repo
	}
	// Case-folded self-compare (round 9): a hand-rolled pointer naming the
	// dir itself with different case is still the dir itself.
	if strings.EqualFold(filepath.Clean(s), filepath.Clean(dir)) {
		return Layout{}, true
	}
	if !filepath.IsAbs(s) {
		// jj's semantics: relative to the .jj directory.
		if jjRel := filepath.Join(dir, ".jj", s); dirExists(jjRel) {
			s = jjRel
		} else {
			s = filepath.Clean(filepath.Join(dir, s))
		}
	}
	l := Layout{RepoDir: s}
	// The parent ROOT: colocated layouts end .jj\repo; split layouts name
	// a store under .jj\repo\store\...  -  the owning root is the first
	// .jj-repo ancestor's parent either way.
	l.ParentRoot = parentRootOf(s)
	if strings.EqualFold(filepath.Clean(l.ParentRoot), filepath.Clean(dir)) {
		return Layout{}, true // the dir is its own parent: root repo
	}
	return l, true
}

// parentRootOf maps a repo-dir path to its owning workspace root.
func parentRootOf(repoDir string) string {
	clean := filepath.Clean(repoDir)
	// Colocated: <root>/.jj/repo.
	if strings.HasSuffix(filepath.ToSlash(clean), "/.jj/repo") {
		return filepath.FromSlash(strings.TrimSuffix(filepath.ToSlash(clean), "/.jj/repo"))
	}
	// Split layout: <root>/.jj/repo/store/git...  -  walk up to the .jj/repo
	// element.
	if i := strings.Index(filepath.ToSlash(clean), "/.jj/repo/"); i >= 0 {
		return filepath.FromSlash(filepath.ToSlash(clean)[:i])
	}
	// A pointer naming a bare directory names the repo ROOT itself
	// (hand-rolled split layouts and older jj spellings do this): the dir
	// is the root, not the root's child.
	return clean
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
