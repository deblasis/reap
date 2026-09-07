// Package classify determines what a candidate directory IS. It runs no
// external tools: every decision reads files (the .git file of a linked
// worktree, the parent's worktree metadata, the presence of .jj). That keeps
// classification orthogonal to the facts packages and makes orphan detection
// structural rather than exec-shaped: a missing parent is a fact about the
// filesystem, not an error from git.
//
// The classifier defines no-VCS-markers = scratch, so kind unknown is
// structurally rare and semantically "could not classify"  -  which the
// reachability rules treat as ignorance, not judgment.
package classify

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/deblasis/reap/internal/jjpaths"
)

// Kind enumerates what a candidate is. The verdict matrix keys off these;
// orphaned kinds rank above unreadable-state rows because their detection is
// file-based, not exec-based.
type Kind string

const (
	KindScratch             Kind = "scratch"
	KindGitRepo             Kind = "git-repo"
	KindGitWorktree         Kind = "git-worktree"
	KindGitWorktreeOrphaned Kind = "git-worktree-orphaned"
	KindJJRepo              Kind = "jj-repo"
	KindJJWorkspace         Kind = "jj-workspace"
	KindJJWorkspaceOrphaned Kind = "jj-workspace-orphaned"
	KindUnknown             Kind = "unknown"
)

// Info is the classification result plus the evidence the verdict engine and
// apply need later (ParentRepo for worktree/workspace deregistration and the
// parent-of-live-children checks).
type Info struct {
	Kind       Kind
	ParentRepo string // resolved parent repo root for worktree/workspace kinds
	GitDirFile string // the .git file content target when linked
	// GitBackend reports whether a git backend exists HERE: a root .git dir
	// or a linked .git file. Colocated jj repos have it, split-layout jj
	// repos do not  -  and running git facts where no backend exists yields a
	// bogus state-unreadable that shadows the jj rows for that whole
	// population (the round-2 finding both seats disproved live).
	GitBackend bool
}

// Dir classifies one candidate directory.
func Dir(path string) Info {
	hasGit := dirExists(filepath.Join(path, ".git"))
	gitFile, isLinked := readGitLink(path)
	hasJJ := dirExists(filepath.Join(path, ".jj"))

	switch {
	case hasJJ && hasGit:
		// Colocated jj repo: the git dir and jj repo share the root.
		return Info{Kind: KindJJRepo, ParentRepo: path, GitBackend: true}
	case hasJJ && isLinked:
		// A jj workspace whose working copy is also a linked git worktree
		// (the common `jj workspace add` shape in a colocated repo).
		info := classifyJJWorkspace(path, gitFile)
		info.GitBackend = true
		return info
	case hasJJ:
		return classifyJJStandalone(path)
	case hasGit:
		return Info{Kind: KindGitRepo, ParentRepo: path, GitBackend: true}
	case isLinked:
		info := classifyWorktree(path, gitFile)
		info.GitBackend = info.Kind == KindGitWorktree // orphaned-by-parent-gone has no reachable backend
		return info
	default:
		if readable(path) {
			return Info{Kind: KindScratch}
		}
		return Info{Kind: KindUnknown}
	}
}

// classifyWorktree resolves a linked worktree's parent from its .git file.
// Orphan detection is deliberately file-based: the parent's .git must exist
// AND the worktree's registration inside it must carry a resolvable HEAD
// (loose ref or packed-refs entry). A worktree whose branch was deleted from
// the parent (the so755 class: parent alive, git commands fail) is detected
// here by the missing ref, not by an exec failure later.
func classifyWorktree(path, gitFile string) Info {
	info := Info{Kind: KindGitWorktreeOrphaned, GitDirFile: gitFile}
	parent, wtName, ok := worktreeParent(gitFile)
	if !ok {
		return info
	}
	info.ParentRepo = parent
	if !dirExists(filepath.Join(parent, ".git")) {
		return info
	}
	if !worktreeHeadResolvable(parent, wtName) {
		return info
	}
	info.Kind = KindGitWorktree
	return info
}

// classifyJJWorkspace: jj workspace working copies carry .jj plus (in
// colocated setups) a linked .git file. Orphan = the parent repo (from either
// pointer) is gone.
func classifyJJWorkspace(path, gitFile string) Info {
	parent, _, ok := worktreeParent(gitFile)
	if ok && dirExists(filepath.Join(parent, ".git")) {
		return Info{Kind: KindJJWorkspace, ParentRepo: parent, GitDirFile: gitFile}
	}
	// Fall back to the jj pointer: .jj/repo names the main repo in split
	// layouts (the PARENT ROOT via jjpaths  -  the shape jj -R accepts). If
	// neither resolves, orphaned.
	if l, ok := jjpaths.Resolve(path); ok && l.ParentRoot != "" && dirExists(l.ParentRoot) {
		return Info{Kind: KindJJWorkspace, ParentRepo: l.ParentRoot, GitDirFile: gitFile}
	}
	return Info{Kind: KindJJWorkspaceOrphaned, GitDirFile: gitFile}
}

// classifyJJStandalone handles .jj without any .git: a pure jj repo (root
// itself) or a split-layout workspace. Working copies point at the main repo
// via .jj/repo; a root repo's pointer is absent or self-referential.
// ParentRepo carries the parent WORKSPACE ROOT (not the repo dir the
// pointer names verbatim): `jj -R <root>` is the shape every command
// accepts  -  pointing at the repo dir made every workspace forget FAIL live
// (the round-7 engineering major).
func classifyJJStandalone(path string) Info {
	l, ok := jjpaths.Resolve(path)
	if ok && l.ParentRoot != "" {
		if !dirExists(l.ParentRoot) {
			return Info{Kind: KindJJWorkspaceOrphaned}
		}
		return Info{Kind: KindJJWorkspace, ParentRepo: l.ParentRoot}
	}
	// No pointer or a root pointer: the dir is the jj repo itself.
	return Info{Kind: KindJJRepo, ParentRepo: path}
}

// readGitLink returns the gitdir target when path/.git is a file (linked
// worktree) rather than a directory.
func readGitLink(path string) (string, bool) {
	gitPath := filepath.Join(path, ".git")
	fi, err := os.Stat(gitPath)
	if err != nil || fi.IsDir() {
		return "", false
	}
	raw, err := os.ReadFile(gitPath)
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(s, "gitdir:") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(s, "gitdir:")), true
}

// worktreeParent turns a gitdir pointer like
// C:/x/repo/.git/worktrees/<name> into (repo root, worktree name).
func worktreeParent(gitDir string) (parent, wtName string, ok bool) {
	s := filepath.ToSlash(gitDir)
	i := strings.LastIndex(s, "/worktrees/")
	if i < 0 {
		return "", "", false
	}
	parent = filepath.FromSlash(s[:i])
	// parent is .../<repo>/.git or .../<repo>/.git for a bare-style path; strip
	// a trailing /.git to expose the repo root.
	if filepath.Base(parent) == ".git" {
		parent = filepath.Dir(parent)
	}
	wtName = filepath.FromSlash(s[i+len("/worktrees/"):])
	return parent, wtName, wtName != ""
}

// worktreeHeadResolvable checks the parent's registration for the worktree:
// the metadata dir must exist and its HEAD must be either a sha or a ref the
// parent still has (loose or packed). A deleted branch leaves "ref:
// refs/heads/x" with no backing ref  -  broken, orphaned.
func worktreeHeadResolvable(parent, wtName string) bool {
	wtDir := filepath.Join(parent, ".git", "worktrees", wtName)
	if !dirExists(wtDir) {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(wtDir, "HEAD"))
	if err != nil {
		return false
	}
	head := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(head, "ref:") {
		// Detached sha: presence of the HEAD line is all a file-based check
		// can establish; object existence is git's business at facts time.
		return len(head) >= 7
	}
	ref := strings.TrimSpace(strings.TrimPrefix(head, "ref:"))
	if _, err := os.Stat(filepath.Join(parent, ".git", filepath.FromSlash(ref))); err == nil {
		return true
	}
	packed, err := os.ReadFile(filepath.Join(parent, ".git", "packed-refs"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(packed), "\n") {
		if strings.HasSuffix(strings.TrimSpace(line), " "+ref) {
			return true
		}
	}
	return false
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func readable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
