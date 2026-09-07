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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	Created       time.Time  `json:"created"`
	RunID         string     `json:"runId,omitempty"` // reverse lookup from reap.log
	Source        string     `json:"source"`
	Mode          string     `json:"mode"` // bundle | plain-copy
	Origin        string     `json:"origin,omitempty"` // remote URL a delta bundle depends on
	BaseRef       string     `json:"baseRef,omitempty"`
	BaseSHA       string     `json:"baseSha,omitempty"`
	BaseBases     []BaseInfo `json:"baseBases,omitempty"` // per-branch-union bases (branch -> base)
	SelfContained bool       `json:"selfContained"`
	BundleBytes   int64      `json:"bundleBytes,omitempty"`
	Revset        string     `json:"revset,omitempty"` // jj push-state revset (jj captures)
	CaptureRef    string     `json:"captureRef,omitempty"` // refs/reap/capture-*
	Classes       Classes    `json:"classes"`
	Entries       []Entry    `json:"entries,omitempty"` // plain-copy file list
	EmptyDirs     []string  `json:"emptyDirs,omitempty"` // RELATIVE to the source root
	Interleaved   bool       `json:"indexInterleaved,omitempty"`
}

// BaseInfo is one per-branch delta base (the per-branch-union tier).
type BaseInfo struct {
	Branch string `json:"branch"`
	Ref    string `json:"ref"`
	SHA    string `json:"sha"`
}

// Classes records what the snapshot provably contains, per category.
type Classes struct {
	Refs             int   `json:"refs"`             // branch tips pinned
	Tags             int   `json:"tags"`             // tag tips pinned
	ReflogTips       int   `json:"reflogTips"`
	ReflogExpireD    int   `json:"reflogExpireDays,omitempty"`
	StashGens        int   `json:"stashGenerations"`
	JJChanges        int   `json:"jjChanges"`
	DirtyFiles       int   `json:"dirtyFiles"`
	DirtyBytes       int64 `json:"dirtyBytes"`
	UntrackedFiles   int   `json:"untrackedFiles"`
	UntrackedBytes   int64 `json:"untrackedBytes"`
	IgnoredFiles     int   `json:"ignoredFiles"`
	IgnoredBytes     int64 `json:"ignoredBytes"`
}

// Entry is one plain-copy file (name + size), capped in count.
type Entry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// ErrTooLarge reports the snapshot exceeded the cap (dir untouched). The
// copy names the config key: when the cap binds, the operator's remedy is
// quarantine-cap-gb.
type ErrTooLarge struct{ Need, Cap int64 }

func (e *ErrTooLarge) Error() string {
	return fmt.Sprintf("quarantine would need ~%d MB, cap is %d MB (quarantine-cap-gb)", e.Need>>20, e.Cap>>20)
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

// ErrSessionExists reports that the session directory already exists — a
// same-name race from another creator; proceeding would overwrite that
// session's recovery. TYPED (fs.ErrExist) so retries key on collisions,
// never on unrelated mkdir failures like access-denied.
type ErrSessionExists struct{ Dir string }

func (e *ErrSessionExists) Error() string {
	return fmt.Sprintf("session dir %s already exists: a same-named session exists; refusing to overwrite", e.Dir)
}

// Is lets errors.Is(err, fs.ErrExist) match a session collision.
func (e *ErrSessionExists) Is(target error) bool { return target == os.ErrExist }

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
	// MkdirAll): an existing dir of the same name is ANOTHER SESSION —
	// proceeding would overwrite that dir's only recovery copy. A typed
	// collision error (round 4): string-matching the prose burned the retry
	// on unrelated mkdir failures.
	if err := os.Mkdir(sessionDir, 0o755); err != nil {
		if os.IsExist(err) {
			return nil, &ErrSessionExists{Dir: sessionDir}
		}
		return nil, fmt.Errorf("session dir %s: %w", sessionDir, err)
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
	//    source repo and die with it; price the ranges, then materialize
	//    every pinned ref into the session dir as an explicit <base>..<ref>
	//    range list, verify it against the repo that still exists, and
	//    fsync before the caller may delete anything. Pricing runs BEFORE
	//    the write: an over-cap projection refuses without transiently
	//    dumping the payload onto the volume this tool protects.
	bundle := filepath.Join(sessionDir, "bundle.git")
	ranges, err := bundleRanges(gitRunner, source, m, append([]string{m.CaptureRef}, pins...))
	if err != nil {
		removeSession(sessionDir)
		return nil, err
	}
	// Pricing REFUSES on failure too (round 4): a failed or unparseable
	// pre-price must not degrade to write-then-refuse — that path puts the
	// transient bytes on the volume this tool protects before saying no.
	if opts.CapBytes > 0 {
		projected, derr := gitRunner.DiskUsage(source, ranges)
		if derr != nil || projected == 0 && len(ranges) > 0 {
			removeSession(sessionDir)
			return nil, fmt.Errorf("bundle pricing failed (refusing rather than writing unpriced): %w", derr)
		}
		if projected > opts.CapBytes {
			removeSession(sessionDir)
			return nil, &ErrTooLarge{Need: projected, Cap: opts.CapBytes}
		}
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

// findEmptyDirs lists empty directories under root (capped), as paths
// RELATIVE to root: git trees cannot represent them, so the manifest
// records them and restore recreates them under the destination — absolute
// paths there produced invalid joins (the round-2 live probe).
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
			if rel, rerr := filepath.Rel(root, p); rerr == nil {
				out = append(out, rel)
			}
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
// readIndexBytes is a seam: the deterministic interleave fixture swaps it
// to simulate a concurrent git's mid-window write (a live race is
// untestable-reliable; the seam makes the detection provable).
var readIndexBytes = os.ReadFile

func captureRef(r gitx.Runner, dir string, m *Manifest) error {
	preMtime := indexMtime(dir)
	backup, serr := r.SaveIndex(dir)
	if serr != nil {
		return fmt.Errorf("save index: %w (refusing; a reset-based fallback would destroy the operator's staged state)", serr)
	}
	// The saved index BYTES stay in memory: RestoreBackup deletes the
	// backup file, so a post-restore read of it was dead code (the round-3
	// phantom fold the live concurrent-add race proved inert).
	var savedBytes []byte
	idxPath := ""
	if backup != "" {
		if g, ok := gitDirForPath(dir); ok {
			idxPath = filepath.Join(g, "index")
			savedBytes, _ = os.ReadFile(backup)
		}
		// w1: a concurrent git that wrote between SaveIndex and staging is
		// detectable HERE, before reap's own add rewrites the index.
		if len(savedBytes) > 0 && idxPath != "" {
			if cur, cerr := readIndexBytes(idxPath); cerr == nil && !bytes.Equal(savedBytes, cur) {
				m.Interleaved = true
			}
		}
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
	// w2: after the restore, the index on disk must equal the saved bytes —
	// anything else is a concurrent git that wrote past the restore.
	// (The window DURING staging — while git add/plumbing hold the index
	// lock between our steps — is honestly unobservable without holding
	// the lock ourselves, which would deadlock git add; w1+w2 are the two
	// windows reap can see, and both are surfaced.) The restore's own
	// mtime bump is UNDONE so a refused discard does not flip the dir
	// ACTIVE for 48h (the exact feedback loop Reverify fixes for
	// FETCH_HEAD).
	if len(savedBytes) > 0 && idxPath != "" {
		if cur, cerr := readIndexBytes(idxPath); cerr == nil && !bytes.Equal(savedBytes, cur) {
			m.Interleaved = true
		}
	}
	if g, ok := gitDirForPath(dir); ok && !preMtime.IsZero() {
		_ = os.Chtimes(filepath.Join(g, "index"), preMtime, preMtime)
	}
	return nil
}

// gitDirOf resolves the worktree's own git dir or "" when absent.
func gitDirOf(dir string) string {
	g, ok := gitDirForPath(dir)
	if !ok {
		return ""
	}
	return g
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

	// Branch and tag tips: only those whose PEELD commit carries local-only
	// work (a tip fully on a remote is recoverable by re-cloning). An
	// annotated tag's %(objectname) is the tag OBJECT — membership against
	// the unpushed COMMIt set must use the peeled target, or every
	// annotated-tag pin silently drops (the round-2 live data loss). When
	// the unpushed set cannot be computed, EVERYTHING is pinned — the
	// completeness direction.
	tips, err := r.LocalOnlyTips(dir)
	if err != nil {
		return nil, fmt.Errorf("enumerate tips: %w", err)
	}
	unpushed := r.UnpushedCommits(dir)
	for _, tip := range tips {
		member := tip.Peeled
		if member == "" {
			member = tip.SHA
		}
		if unpushed != nil && !unpushed[member] && !unpushed[tip.SHA] {
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
		// Pin the ref's OWN object: for an annotated tag that carries the
		// tag object AND (via the bundle range) its target chain.
		if perr := pin(ref, tip.SHA); perr != nil {
			return nil, perr
		}
		if strings.HasPrefix(tip.Ref, "refs/tags/") {
			m.Classes.Tags++
		} else {
			m.Classes.Refs++
		}
	}

	// Reflog-only generations: post-reset / pre-rebase commits reachable
	// from NO ref — the entire unpushed-reflog BLOCKED class. Reflogs are
	// never packed by bundles, so each ENTRY TIP gets a named pin (the
	// chain under it rides along in the bundle range). Unreadable evidence
	// FAILS the capture: pinning nothing while claiming completeness is
	// the manifest's one forbidden lie.
	reflogTips, rerr := r.ReflogOnlyCommits(dir)
	if rerr != nil {
		return nil, fmt.Errorf("enumerate reflog entries: %w", rerr)
	}
	for i, sha := range reflogTips {
		if perr := pin(fmt.Sprintf("refs/reap/reflog-%d", i), sha); perr != nil {
			return nil, perr
		}
	}
	m.Classes.ReflogTips = len(reflogTips)
	// Days-to-expiry from the OLDEST reflog-only entry tip (90d default
	// expiry, same approximation the verdict's detail uses).
	if dates := r.ReflogEntryDates(dir); len(dates) > 0 {
		oldest := time.Time{}
		for _, sha := range reflogTips {
			if ds, ok := dates[sha]; ok {
				if d, perr := time.Parse(time.RFC3339, ds); perr == nil && (oldest.IsZero() || d.Before(oldest)) {
					oldest = d
				}
			}
		}
		if !oldest.IsZero() {
			days := 90 - int(time.Since(oldest).Hours()/24)
			if days < 0 {
				days = 0
			}
			m.Classes.ReflogExpireD = days
		}
	}

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
	// the git backend so the commits are visible to update-ref. The revset
	// is recorded (spec: "the revset and count go in the manifest").
	if opts.Colocated && opts.JJ.Budget > 0 {
		shas, jerr := opts.JJ.PushStateCommits(dir)
		if jerr != nil {
			return nil, fmt.Errorf("jj push state: %w", jerr)
		}
		m.Revset = "::@ ~ ::remote_bookmarks()"
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
// (a bare ref = a full, self-contained history). Two capture-time
// decisions per the spec: (1) the base must still be ADVERTISED by the
// recorded remote (one ls-remote) — a base that is not advertised may be
// gone (force-push/squash-merge), and shipping a delta whose recovery
// depends on it would be a bundle that verifies yet never restores; the
// safe fallback in both the gone and the merely-advanced case is the
// self-contained form (bigger, but complete either way; if that exceeds
// the cap, the caller refuses with the dir still on disk). (2) per-branch
// bases are RECORDED with their SHAs so revalidation and restore can name
// real prerequisites.
func bundleRanges(r gitx.Runner, dir string, m *Manifest, refs []string) ([]string, error) {
	m.Origin = r.RemoteURL(dir)
	if m.Origin == "" {
		if remotes := r.Remotes(dir); len(remotes) > 0 {
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
	selfContained := func() ([]string, error) {
		m.BaseRef, m.BaseSHA, m.BaseBases, m.SelfContained = "", "", nil, true
		return rangesFor(""), nil
	}
	// Capture-time revalidation: no remote to ask, or base not advertised
	// (gone OR merely advanced — indistinguishable without a fetch, and
	// self-contained is correct in both) -> self-contained form.
	baseAdvertised := func(ref, sha string) bool {
		if m.Origin == "" || sha == "" {
			return m.Origin == "" // no remote at all: self-contained by shape
		}
		out, err := r.LSRemote(m.Origin)
		if err != nil {
			// Offline at capture time: the base cannot be confirmed —
			// self-contained, never an unverifiable delta.
			return false
		}
		return strings.Contains(out, sha)
	}

	if up := r.UpstreamRef(dir); up != "" && r.ResolveRef(dir, up) != "" {
		sha := r.ResolveRef(dir, up)
		if !baseAdvertised(up, sha) {
			return selfContained()
		}
		m.BaseRef, m.BaseSHA, m.SelfContained = up, sha, false
		return rangesFor(up), nil
	}
	if sha := r.ResolveRef(dir, "refs/remotes/origin/HEAD"); sha != "" {
		if !baseAdvertised("refs/remotes/origin/HEAD", sha) {
			return selfContained()
		}
		m.BaseRef, m.BaseSHA, m.SelfContained = "refs/remotes/origin/HEAD", sha, false
		return rangesFor("refs/remotes/origin/HEAD"), nil
	}
	// Per-branch union: branches with their own upstream price against it
	// (each base recorded AND revalidated — round 4 closed the gap where
	// this tier skipped the capture-time baseAdvertised check the first
	// two tiers get; a gone per-branch base now carries that ref whole);
	// everything else is carried whole.
	if ups := r.BranchUpstreams(dir); len(ups) > 0 {
		m.BaseRef, m.SelfContained = "per-branch", false
		out := make([]string, 0, len(refs))
		for _, ref := range refs {
			base, baseSHA := "", ""
			if strings.HasPrefix(ref, "refs/reap/unpushed-") {
				if up, ok := ups[strings.TrimPrefix(ref, "refs/reap/unpushed-")]; ok {
					sha := r.ResolveRef(dir, up)
					if sha != "" && baseAdvertised(up, sha) {
						base, baseSHA = up, sha
					}
				}
			}
			if base != "" {
				m.BaseBases = append(m.BaseBases, BaseInfo{
					Branch: strings.TrimPrefix(ref, "refs/reap/unpushed-"), Ref: base, SHA: baseSHA})
				out = append(out, base+".."+ref)
			} else {
				out = append(out, ref)
			}
		}
		if len(m.BaseBases) > 0 && m.BaseSHA == "" {
			m.BaseSHA = m.BaseBases[0].SHA
		}
		return out, nil
	}
	return selfContained()
}

func (m *Manifest) account(r gitx.Runner, dir string) error {
	st, err := r.StatusPorcelain(dir)
	if err != nil {
		return fmt.Errorf("status for manifest accounting: %w", err)
	}
	m.Classes.DirtyFiles = st.Dirty
	m.Classes.DirtyBytes = st.DirtyBytes
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
// included) before anything is written; the session dir is created
// EXCLUSIVELY (same collision contract as Snapshot — round 4); every
// copied file is FSYNCED (the plain copy is often the ONLY recovery, and
// it was the one artifact class that was not fsynced); BundleBytes carries
// the copy's size so callers can decrement their free-space budgets.
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
	m.Entries, m.EmptyDirs, m.BundleBytes = files, emptyDirs, total
	if serr := os.Mkdir(sessionDir, 0o755); serr != nil {
		if os.IsExist(serr) {
			return nil, &ErrSessionExists{Dir: sessionDir}
		}
		return nil, fmt.Errorf("session dir %s: %w", sessionDir, serr)
	}
	if err := copyTree(source, filepath.Join(sessionDir, "files")); err != nil {
		removeSession(sessionDir)
		return nil, err
	}
	// Sweep-fsync the copied tree + the manifest: a power cut in the
	// delete-that-follows window must not tear the only recovery copy.
	if err := fsyncTree(filepath.Join(sessionDir, "files")); err != nil {
		removeSession(sessionDir)
		return nil, err
	}
	if err := writeManifest(sessionDir, m); err != nil {
		removeSession(sessionDir)
		return nil, err
	}
	if err := syncFile(filepath.Join(sessionDir, "manifest.json")); err != nil {
		removeSession(sessionDir)
		return nil, err
	}
	return m, nil
}

// fsyncTree flushes every file under root (plain-copy durability).
func fsyncTree(root string) error {
	return filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		f, oerr := os.OpenFile(p, os.O_RDWR, 0)
		if oerr != nil {
			return nil // best-effort: closed files still readable
		}
		defer f.Close()
		return f.Sync()
	})
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
		// Streamed, not buffered whole: a near-cap single file must not
		// spike RSS by its size.
		in, oerr := os.Open(p)
		if oerr != nil {
			return oerr
		}
		defer in.Close()
		out, cerr := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if cerr != nil {
			return cerr
		}
		if _, cerr = io.Copy(out, in); cerr != nil {
			out.Close()
			return cerr
		}
		return out.Close()
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

// Revalidate checks a delta bundle's base(s) against its recorded remote
// with one ls-remote: every recorded base SHA still advertised =
// verified-ok; the remote reachable but a base not among its advertised
// tips = at-risk (likely force-push/squash-merge — recovery through the
// remote is ending); unreachable remote = unverified (offline/auth — NOT
// at-risk). One ls-remote cannot prove ancestry, so "advertised" is the
// approximation the spec's budget allows (restore itself fetch-then-
// verifies and never refuses on advancement); self-contained bundles are
// verified-ok by construction.
func Revalidate(r gitx.Runner, m *Manifest) RestoreVerdict {
	if m == nil {
		return Unverified
	}
	if m.SelfContained || (m.BaseSHA == "" && len(m.BaseBases) == 0) {
		return VerifiedOK
	}
	out, err := r.LSRemote(m.Origin)
	if err != nil {
		return Unverified
	}
	bases := map[string]bool{m.BaseSHA: true}
	for _, b := range m.BaseBases {
		bases[b.SHA] = true
	}
	for sha := range bases {
		if sha == "" {
			continue
		}
		if !strings.Contains(out, sha) {
			return AtRisk
		}
	}
	return VerifiedOK
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
