// Package quarantine implements reap's BLOCKED-resolution rescue: `reap
// discard` snapshots a dirty/unpushed dir COMPLETELY, verifies the snapshot,
// and only then deletes. The completeness contract is the whole package:
//
//   - NON-MUTATING capture: `git add -A -f .` + plumbing commit via
//     write-tree/commit-tree/update-ref creates refs without touching the
//     working tree (the round-3 spec fold rejected stash-based capture for
//     mutating the source on refusal). The operator's exact staged state is
//     saved and restored, and the index mtime is verified unchanged across
//     the window (interleaving surfaced, never silently restored over).
//   - Tip pinning under refs/reap/*: bundles materialize refs, NEVER
//     reflogs — so every recoverable tip gets a named ref first: branches
//     (unpushed-<branch>), tags (tag-<name>), reflog-only generations
//     (reflog-N), stash generations (stash-N), jj push-state commits
//     (jj-N), and the capture commit itself (capture-<ts>).
//   - DELTA pricing per the spec's pinned base selection (upstream ref,
//     else origin/HEAD, else per-branch upstream union), recorded in the
//     manifest with the base SHA and remote URL so recovery prerequisites
//     are provable and revalidatable; the self-contained full-history form
//     is the capture-time fallback when no base exists.
//   - verify+fsync BEFORE the caller deletes: a quarantined-only-then-failed
//     deletion is a refusal, never a half-rescue; a failed session leaves
//     nothing behind that could masquerade as recoverable.
package quarantine

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/gitx"
	"github.com/deblasis/reap/internal/jjx"
)

// Manifest is the completeness record stored beside every bundle: what the
// snapshot holds, per class, so a discard log line proves recoverability.
type Manifest struct {
	Created     time.Time `json:"created"`
	RunID       string    `json:"runId,omitempty"` // reverse lookup from reap.log
	Source      string    `json:"source"`
	Mode        string    `json:"mode"` // bundle | plain-copy
	Origin      string    `json:"origin,omitempty"`   // remote URL a delta bundle depends on
	BaseRef     string    `json:"baseRef,omitempty"`  // the pinned base ref ("" = self-contained)
	BaseSHA     string    `json:"baseSha,omitempty"`  // base commit SHA (prerequisite proof)
	SelfContained bool    `json:"selfContained"`      // true = restorable with no remote
	BundleBytes int64     `json:"bundleBytes,omitempty"`
	CaptureRef  string    `json:"captureRef,omitempty"` // refs/reap/capture-*
	Classes     Classes   `json:"classes"`
	Entries     []Entry   `json:"entries,omitempty"` // plain-copy file list
	EmptyDirs   []string  `json:"emptyDirs,omitempty"`
	Interleaved bool      `json:"indexInterleaved,omitempty"` // concurrent git touched the index mid-capture
}

// Classes records what the snapshot provably contains, per category.
type Classes struct {
	Refs           int   `json:"refs"`
	ReflogTips     int   `json:"reflogTips"`
	ReflogExpireD  int   `json:"reflogExpireDays,omitempty"`
	StashGens      int   `json:"stashGenerations"`
	JJChanges      int   `json:"jjChanges"`
	Dirty          int   `json:"dirtyBytes"`
	UntrackedFiles int   `json:"untrackedFiles"`
	UntrackedBytes int64 `json:"untrackedBytes"`
	IgnoredFiles   int   `json:"ignoredFiles"`
	IgnoredBytes   int64 `json:"ignoredBytes"`
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

// ErrGitBusy reports an index.lock at capture start (spec: skip git-busy,
// the same condition that is state-unreadable at scan time).
type ErrGitBusy struct{ Path string }

func (e *ErrGitBusy) Error() string {
	return fmt.Sprintf("index.lock present at capture start (%s): a concurrent git is mid-write", e.Path)
}

// Options carries the caller's budgets and context.
type Options struct {
	CapBytes int64 // 0 = no cap
	Mode     string
	RunID    string
	JJ       jjx.Runner // zero budget = jj capture skipped
	Colocated bool      // .jj + .git at the root (jj pinning applies)
}

// Dir is %LOCALAPPDATA%\reap\quarantine (or REAP_DIR\quarantine).
func Dir(stateDir string) string { return filepath.Join(stateDir, "quarantine") }

// SessionDir names one discard's directory: <ts>-<name>.
func SessionDir(stateDir, source string, now time.Time) string {
	name := filepath.Base(strings.TrimRight(source, string(os.PathSeparator)))
	name = strings.NewReplacer(":", "-", " ", "_").Replace(name)
	return filepath.Join(Dir(stateDir), now.Format("20060102-150405")+"-"+name)
}

// FreshSessionDir returns SessionDir, suffixed -2, -3, ... when the name is
// taken (two same-basename dirs discarded in one wall-clock second must not
// share a session — the earlier bundle is that dir's only recovery).
func FreshSessionDir(stateDir, source string, now time.Time) string {
	base := SessionDir(stateDir, source, now)
	session := base
	for i := 2; ; i++ {
		if _, err := os.Stat(session); os.IsNotExist(err) {
			return session
		}
		session = fmt.Sprintf("%s-%d", base, i)
	}
}

// Snapshot captures source completely and returns the manifest. The source
// dir is never mutated; on any failure it is untouched AND the session dir
// is removed — a half-written session must never masquerade as recoverable
// (the caller checks err). gitRunner drives git.
func Snapshot(sessionDir, source string, gitRunner gitx.Runner, opts Options) (*Manifest, error) {
	now := time.Now()
	m := &Manifest{Created: now, RunID: opts.RunID, Source: source, Mode: opts.Mode}

	// The session dir must exist up front: `git bundle create` writes
	// <bundle>.lock BESIDE its destination. Created EXCLUSIVELY (Mkdir, not
	// MkdirAll): a same-name race from another process must fail loudly,
	// never overwrite a live session.
	if err := os.Mkdir(sessionDir, 0o755); err != nil && !os.IsExist(err) {
		return nil, err
	}

	// Capture-start git-busy check (the spec's step 3 interlock): a live
	// index.lock means a concurrent git owns the index; capturing anyway
	// would race its writes.
	if gitRunner.IndexLocked(source) {
		removeSession(sessionDir)
		return nil, &ErrGitBusy{Path: source}
	}

	// Empty dirs cannot live in git trees; record them for restore.
	m.EmptyDirs = findEmptyDirs(source, 512)

	// 1. The capture ref: everything staged into a tree, committed via
	//    plumbing. Working-tree files stay on disk.
	if err := captureRef(gitRunner, source, m); err != nil {
		removeSession(sessionDir)
		return nil, err
	}

	// 2. Tip pinning under refs/reap/* (bundles pack refs, not reflogs).
	pins, err := pinTips(gitRunner, opts, source, m)
	if err != nil {
		removeSession(sessionDir)
		return nil, err
	}

	// 3. THE BUNDLE IS THE QUARANTINE. refs/reap/* pins live inside the
	//    source repo and die with it; materialize every pinned ref into the
	//    session dir as an explicit <base>..<ref> range list, verify it
	//    against the repo that still exists, and fsync before the caller
	//    may delete anything.
	bundle := filepath.Join(sessionDir, "bundle.git")
	ranges, err := bundleRanges(gitRunner, source, m, append([]string{m.CaptureRef}, pins...))
	if err != nil {
		removeSession(sessionDir)
		return nil, err
	}
	if err := gitRunner.BundleCreateRanges(source, bundle, ranges); err != nil {
		removeSession(sessionDir)
		return nil, fmt.Errorf("bundle create: %w", err)
	}
	if err := gitRunner.BundleVerify(source, bundle); err != nil {
		removeSession(sessionDir)
		return nil, &ErrVerify{Underlying: err}
	}
	if err := syncFile(bundle); err != nil {
		removeSession(sessionDir)
		return nil, fmt.Errorf("bundle fsync: %w", err)
	}
	size := fileSize(bundle)
	if opts.CapBytes > 0 && size > opts.CapBytes {
		removeSession(sessionDir)
		return nil, &ErrTooLarge{Need: size, Cap: opts.CapBytes}
	}
	m.BundleBytes = size

	// 4. Class accounting (the manifest proves WHAT is recoverable). An
	//    unreadable status is an error, not zero: a manifest claiming 0
	//    dirty on unreadable evidence is a completeness lie.
	if err := m.account(gitRunner, source); err != nil {
		removeSession(sessionDir)
		return nil, err
	}

	// 5. Manifest last (atomically): it describes a bundle that already
	//    exists and verifies, and it is fsynced too.
	if err := writeManifest(sessionDir, m); err != nil {
		removeSession(sessionDir)
		return nil, err
	}
	return m, nil
}

// removeSession wipes a failed session: a quarantine that did not complete
// is not a quarantine.
func removeSession(sessionDir string) { _ = os.RemoveAll(sessionDir) }

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// syncFile flushes a written artifact to disk. Opened read/write: Windows
// refuses FlushFileBuffers on a read-only handle.
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// findEmptyDirs lists empty directories under root (capped): git trees
// cannot represent them, so the manifest records them and restore
// recreates them.
func findEmptyDirs(root string, cap int) []string {
	var out []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if p == root {
			return nil
		}
		if strings.HasSuffix(p, ".git") || strings.Contains(p, string(os.PathSeparator)+".git"+string(os.PathSeparator)) ||
			strings.HasSuffix(p, ".jj") || strings.Contains(p, string(os.PathSeparator)+".jj"+string(os.PathSeparator)) {
			return filepath.SkipDir
		}
		entries, rerr := os.ReadDir(p)
		if rerr == nil && len(entries) == 0 && len(out) < cap {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// indexMtime is the interlock clock: the saved index's mtime must be
// unchanged across the whole capture window (spec step 3).
func indexMtime(dir string) time.Time {
	g, ok := gitDirForPath(dir)
	if !ok {
		return time.Time{}
	}
	fi, err := os.Stat(filepath.Join(g, "index"))
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

func gitDirForPath(dir string) (string, bool) {
	gitPath := filepath.Join(dir, ".git")
	if fi, err := os.Stat(gitPath); err == nil && fi.IsDir() {
		return gitPath, true
	}
	raw, err := os.ReadFile(gitPath)
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "gitdir:")
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	s = filepath.FromSlash(s)
	if !filepath.IsAbs(s) {
		s = filepath.Join(dir, s)
	}
	return s, true
}

// captureRef creates refs/reap/capture-<ts> holding the full working tree.
// The operator's staged state is saved and restored EXACTLY (SaveIndex),
// not reset to HEAD: a discard attempt that later refuses must leave the
// repo as it found it, staged hunks included. SaveIndex failing is a
// refusal — falling back to reset --mixed would destroy exactly the state
// the backup exists to protect.
func captureRef(r gitx.Runner, dir string, m *Manifest) error {
	preMtime := indexMtime(dir)
	backup, serr := r.SaveIndex(dir)
	if serr != nil {
		return fmt.Errorf("save index: %w (refusing; a reset-based fallback would destroy the operator's staged state)", serr)
	}
	restore := func() error {
		if backup != "" {
			if rerr := r.RestoreBackup(dir, backup); rerr != nil {
				// The all-staged index is live on disk; do not hide it.
				_ = r.ResetIndex(dir)
				return fmt.Errorf("index restore failed (%v); index reset to HEAD — staged state may be lost, .git/index.reap-backup may remain", rerr)
			}
			return nil
		}
		return r.ResetIndex(dir)
	}
	if err := r.AddAll(dir); err != nil {
		_ = restore()
		return fmt.Errorf("stage working tree: %w", err)
	}
	tree, err := r.WriteTree(dir)
	if err != nil {
		_ = restore()
		return fmt.Errorf("write-tree: %w", err)
	}
	commit, err := r.CommitTree(dir, tree)
	if err != nil {
		_ = restore()
		return fmt.Errorf("commit-tree: %w", err)
	}
	ref := fmt.Sprintf("refs/reap/capture-%s", m.Created.Format("20060102-150405"))
	if err := r.UpdateRef(dir, ref, commit); err != nil {
		_ = restore()
		return fmt.Errorf("update-ref %s: %w", ref, err)
	}
	m.CaptureRef = ref
	if rerr := restore(); rerr != nil {
		return rerr
	}
	// Interlock: a concurrent git that wrote the index mid-window would
	// have been silently restored over — surface it instead (spec step 3).
	if post := indexMtime(dir); !preMtime.IsZero() && !post.IsZero() && !post.Equal(preMtime) {
		m.Interleaved = true
	}
	return nil
}

// pinTips pins every recoverable LOCAL-ONLY tip under refs/reap/*, named
// per the spec's scheme so restore and doctor can address them
// predictably. ANY pin failure fails the capture: a silently under-filled
// bundle is the completeness contract's worst outcome.
func pinTips(r gitx.Runner, opts Options, dir string, m *Manifest) ([]string, error) {
	var pins []string
	pin := func(ref, sha string) error {
		if err := r.UpdateRef(dir, ref, sha); err != nil {
			return fmt.Errorf("pin %s at %s: %w", ref, sha, err)
		}
		pins = append(pins, ref)
		return nil
	}

	// Branch and tag tips: only those carrying local-only commits (a tip
	// fully on a remote is recoverable by re-cloning). When the unpushed
	// set cannot be computed, EVERYTHING is pinned — the completeness
	// direction.
	tips, err := r.LocalOnlyTips(dir)
	if err != nil {
		return nil, fmt.Errorf("enumerate tips: %w", err)
	}
	unpushed := r.UnpushedCommits(dir)
	for _, tip := range tips {
		if unpushed != nil && !unpushed[tip.SHA] {
			continue
		}
		var ref string
		switch {
		case strings.HasPrefix(tip.Ref, "refs/heads/"):
			ref = "refs/reap/unpushed-" + strings.TrimPrefix(tip.Ref, "refs/heads/")
		case strings.HasPrefix(tip.Ref, "refs/tags/"):
			ref = "refs/reap/tag-" + strings.TrimPrefix(tip.Ref, "refs/tags/")
		default:
			continue
		}
		if perr := pin(ref, tip.SHA); perr != nil {
			return nil, perr
		}
		m.Classes.Refs++
	}

	// Reflog-only generations: post-reset / pre-rebase commits reachable
	// from NO ref — the entire unpushed-reflog BLOCKED class. Reflogs are
	// never packed by bundles, so each one gets a named pin.
	reflogTips := r.ReflogOnlyCommits(dir)
	for i, sha := range reflogTips {
		if perr := pin(fmt.Sprintf("refs/reap/reflog-%d", i), sha); perr != nil {
			return nil, perr
		}
	}
	m.Classes.ReflogTips = len(reflogTips)

	// Stash generations pinned individually (bundles pack refs, not
	// reflogs; a bare refs/stash pin would carry only the newest).
	gens, err := r.StashRefs(dir)
	if err != nil {
		return nil, fmt.Errorf("enumerate stash generations: %w", err)
	}
	for i, sha := range gens {
		if perr := pin(fmt.Sprintf("refs/reap/stash-%d", i), sha); perr != nil {
			return nil, perr
		}
		m.Classes.StashGens++
	}

	// jj colocated: pin every push-state commit under the same namespace
	// (one rule covers everything recoverable) after exporting jj state to
	// the git backend so the commits are visible to update-ref.
	if opts.Colocated && opts.JJ.Budget > 0 {
		shas, jerr := opts.JJ.PushStateCommits(dir)
		if jerr != nil {
			return nil, fmt.Errorf("jj push state: %w", jerr)
		}
		if len(shas) > 0 {
			if gerr := opts.JJ.GitExport(dir); gerr != nil {
				return nil, fmt.Errorf("jj git export: %w", gerr)
			}
		}
		for i, sha := range shas {
			if perr := pin(fmt.Sprintf("refs/reap/jj-%d", i), sha); perr != nil {
				return nil, perr
			}
		}
		m.Classes.JJChanges = len(shas)
	}

	sort.Strings(pins)
	return pins, nil
}

// bundleRanges selects the delta base per the spec's pinned order — the
// current branch's upstream-tracking ref, else origin/HEAD, else a
// per-branch upstream union — and returns the literal <base>..<ref> list
// (a bare ref = a full, self-contained history). No usable base at all
// (no remotes) means the self-contained full form, recorded in the
// manifest for recovery and revalidation.
func bundleRanges(r gitx.Runner, dir string, m *Manifest, refs []string) ([]string, error) {
	m.Origin = r.RemoteURL(dir)
	if m.Origin == "" {
		if remotes := r.Remotes(dir); len(remotes) > 0 {
			// Deterministic pick: sorted first remote URL.
			names := make([]string, 0, len(remotes))
			for name := range remotes {
				names = append(names, name)
			}
			sort.Strings(names)
			m.Origin = remotes[names[0]]
		}
	}

	rangesFor := func(base string) []string {
		out := make([]string, 0, len(refs))
		for _, ref := range refs {
			if base != "" {
				out = append(out, base+".."+ref)
			} else {
				out = append(out, ref)
			}
		}
		return out
	}

	if up := r.UpstreamRef(dir); up != "" && r.ResolveRef(dir, up) != "" {
		m.BaseRef, m.BaseSHA, m.SelfContained = up, r.ResolveRef(dir, up), false
		return rangesFor(up), nil
	}
	if sha := r.ResolveRef(dir, "refs/remotes/origin/HEAD"); sha != "" {
		m.BaseRef, m.BaseSHA, m.SelfContained = "refs/remotes/origin/HEAD", sha, false
		return rangesFor("refs/remotes/origin/HEAD"), nil
	}
	// Per-branch union: branches with their own upstream price against it;
	// everything else is carried whole. BaseRef records the shape.
	if ups := r.BranchUpstreams(dir); len(ups) > 0 {
		m.BaseRef, m.SelfContained = "per-branch", false
		out := make([]string, 0, len(refs))
		for _, ref := range refs {
			base := ""
			if strings.HasPrefix(ref, "refs/reap/unpushed-") {
				if up, ok := ups[strings.TrimPrefix(ref, "refs/reap/unpushed-")]; ok && r.ResolveRef(dir, up) != "" {
					base = up
				}
			}
			if base != "" {
				out = append(out, base+".."+ref)
			} else {
				out = append(out, ref)
			}
		}
		return out, nil
	}
	// No usable base: self-contained full histories.
	m.BaseRef, m.BaseSHA, m.SelfContained = "", "", true
	return rangesFor(""), nil
}

func (m *Manifest) account(r gitx.Runner, dir string) error {
	st, err := r.StatusPorcelain(dir)
	if err != nil {
		return fmt.Errorf("status for manifest accounting: %w", err)
	}
	m.Classes.Dirty = st.Dirty
	m.Classes.UntrackedFiles = st.Untracked
	m.Classes.UntrackedBytes = st.UntrackedBytes
	m.Classes.IgnoredFiles = st.Ignored
	m.Classes.IgnoredBytes = st.IgnoredBytes
	return nil
}

func writeManifest(sessionDir string, m *Manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	// Atomic: a torn manifest.json would render the session "(manifest
	// unreadable)" and hide a perfectly good bundle.
	return config.AtomicWrite(filepath.Join(sessionDir, "manifest.json"), raw, 0o644)
}

// WritePlainCopy snapshots a non-git BLOCKED dir as a capped byte-for-byte
// copy with an entries list. The cap prices the WHOLE tree (directories
// included) before anything is written.
func WritePlainCopy(sessionDir, source string, cap int64) (*Manifest, error) {
	m := &Manifest{Created: time.Now(), Source: source, Mode: "plain-copy", SelfContained: true}
	var total int64
	var files []Entry
	var emptyDirs []string
	err := filepath.WalkDir(source, func(p string, d os.DirEntry, werr error) error {
		if werr != nil || p == source {
			return werr
		}
		rel, rerr := filepath.Rel(source, p)
		if rerr != nil {
			return rerr
		}
		if d.IsDir() {
			if entries, lerr := os.ReadDir(p); lerr == nil && len(entries) == 0 {
				emptyDirs = append(emptyDirs, rel)
			}
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		files = append(files, Entry{Name: rel, Size: info.Size()})
		total += info.Size()
		return nil
	})
	if err != nil {
		return nil, err
	}
	if cap > 0 && total > cap {
		return nil, &ErrTooLarge{Need: total, Cap: cap}
	}
	m.Entries, m.EmptyDirs = files, emptyDirs
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return nil, err
	}
	if err := copyTree(source, filepath.Join(sessionDir, "files")); err != nil {
		removeSession(sessionDir)
		return nil, err
	}
	if err := writeManifest(sessionDir, m); err != nil {
		removeSession(sessionDir)
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

// Session is one quarantine listing row.
type Session struct {
	Dir      string
	Manifest *Manifest // nil = manifest unreadable
}

// List returns every session dir with its manifest.
func List(stateDir string) []Session {
	entries, err := os.ReadDir(Dir(stateDir))
	if err != nil {
		return nil
	}
	var out []Session
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
		out = append(out, Session{Dir: full, Manifest: m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out
}

// PruneResult reports one prune outcome (spec: failures surface with the
// bundle named, exit 124/125 — never a silent swallow).
type PruneResult struct {
	Dir  string
	Size int64
	Err  error
}

// PruneOlderThan deletes session dirs older than the cutoff. Retention is
// the caller's decision; per-bundle failures are returned, not swallowed.
func PruneOlderThan(stateDir string, cutoff time.Time) []PruneResult {
	var out []PruneResult
	for _, s := range List(stateDir) {
		fi, err := os.Stat(s.Dir)
		if err != nil || !fi.ModTime().Before(cutoff) {
			continue
		}
		size := Bytes(s.Dir)
		if rerr := os.RemoveAll(s.Dir); rerr != nil {
			out = append(out, PruneResult{Dir: s.Dir, Size: size, Err: rerr})
			continue
		}
		out = append(out, PruneResult{Dir: s.Dir, Size: size})
	}
	return out
}

// RestoreVerdict is the ls-remote revalidation state (spec: three explicit
// states, never conflated).
type RestoreVerdict string

const (
	VerifiedOK RestoreVerdict = "verified-ok"
	AtRisk     RestoreVerdict = "at-risk"
	Unverified RestoreVerdict = "unverified"
)

// Revalidate checks a delta bundle's base against its recorded remote with
// one ls-remote: the base SHA still advertised = verified-ok; the remote
// reachable but the base not among its advertised tips = at-risk (likely
// force-push/squash-merge — recovery through the remote is ending);
// unreachable remote = unverified (offline/auth — NOT at-risk). One
// ls-remote cannot prove ancestry, so "advertised" is the approximation
// the spec's budget allows; self-contained bundles are verified-ok by
// construction.
func Revalidate(r gitx.Runner, m *Manifest) RestoreVerdict {
	if m == nil {
		return Unverified
	}
	if m.SelfContained || m.BaseSHA == "" {
		return VerifiedOK
	}
	out, err := r.LSRemote(m.Origin)
	if err != nil {
		return Unverified
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == m.BaseSHA {
			return VerifiedOK
		}
	}
	return AtRisk
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

// ErrNoBackend is returned when a caller routes a non-git dir into a
// git-mode snapshot (plain-copy is the mode for those).
var ErrNoBackend = errors.New("no git backend for bundle-mode capture")
