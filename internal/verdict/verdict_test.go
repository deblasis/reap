package verdict

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/ghx"
	"github.com/deblasis/reap/internal/gitx"
)

func thresholds() config.Thresholds { return config.Default().Thresholds }

func daysAgo(now time.Time, d int) time.Time { return now.Add(-time.Duration(d) * 24 * time.Hour) }

// cleanGit is the all-clear fact set every fixture mutates.
func cleanGit() *gitx.Facts {
	return &gitx.Facts{Branch: "main", Upstream: "origin/main"}
}

func cleanPR() *ghx.PRHeads {
	h := ghx.NewHeads(map[string]map[string]bool{})
	return &h
}

func scratchInput(now time.Time) Input {
	return Input{
		Kind:         classify.KindScratch,
		LastActivity: daysAgo(now, 30),
		Thresholds:   thresholds(),
		Now:          now,
	}
}

func gitInput(now time.Time) Input {
	return Input{
		Kind:         classify.KindGitRepo,
		LastActivity: daysAgo(now, 30),
		Git:          cleanGit(),
		PRHeads:      cleanPR(),
		RemoteSlugs:  []string{"deblasis/reap-test"},
		Thresholds:   thresholds(),
		Now:          now,
	}
}

func TestKeepRows(t *testing.T) {
	now := time.Now()
	for name, in := range map[string]Input{
		"held":      {Held: true, Thresholds: thresholds(), Now: now},
		"protected": {Protected: true, Thresholds: thresholds(), Now: now},
		"reparse":   {IsReparse: true, Thresholds: thresholds(), Now: now},
	} {
		v := Decide(in)
		if v.Verdict != Keep {
			t.Errorf("%s: verdict = %s, want KEEP", name, v.Verdict)
		}
	}
}

func TestActiveRows(t *testing.T) {
	now := time.Now()
	in := scratchInput(now)
	in.LastActivity = now.Add(-1 * time.Hour)
	if v := Decide(in); v.Verdict != Active || v.Code != "active" {
		t.Fatalf("recent touch: %s/%s", v.Verdict, v.Code)
	}
	in = scratchInput(now)
	in.IncodaLive = true
	if v := Decide(in); v.Verdict != Active || v.Code != "incoda-live" {
		t.Fatalf("incoda live: %s/%s", v.Verdict, v.Code)
	}
}

func TestScratchTiers(t *testing.T) {
	now := time.Now()
	cases := []struct {
		days        int
		wantV, code string
	}{
		{30, Safe, "scratch-idle"},
		{12, Manual, "scratch-recent"},
		{3, Active, "scratch-fresh"},
	}
	for _, c := range cases {
		in := scratchInput(now)
		in.LastActivity = daysAgo(now, c.days)
		v := Decide(in)
		if v.Verdict != c.wantV || v.Code != c.code {
			t.Errorf("scratch %dd: %s/%s, want %s/%s", c.days, v.Verdict, v.Code, c.wantV, c.code)
		}
	}
}

func TestBlockedRowsAndReachability(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		mut  func(*Input)
		code string
	}{
		{"dirty", func(i *Input) { i.Git.Dirty = 5 }, "dirty-files"},
		{"untracked", func(i *Input) { i.Git.Untracked = 2 }, "dirty-files"},
		{"stashes", func(i *Input) { i.Git.Stashes = 1 }, "stashes"},
		{"unpushed", func(i *Input) { i.Git.Unpushed = 321 }, "unpushed-commits"},
		{"reflog-only", func(i *Input) { i.Git.ReflogOnly = 4; i.Git.ExpireDays = 86 }, "unpushed-reflog"},
		{"no-remote", func(i *Input) { i.Git.NoRemote = true }, "no-remote"},
		{"open-pr", func(i *Input) {
			h := ghx.NewHeads(map[string]map[string]bool{
				"deblasis/reap-test": {"feat/x": true},
			})
			i.PRHeads = &h
			i.Git.Branch = "feat/x"
		}, "open-pr"},
	}
	for _, c := range cases {
		in := gitInput(now)
		c.mut(&in)
		v := Decide(in)
		if v.Verdict != Blocked || v.Code != c.code {
			t.Errorf("%s: %s/%s, want BLOCKED/%s", c.name, v.Verdict, v.Code, c.code)
		}
		if v.BlockedClassFact == "" {
			t.Errorf("%s: BlockedClassFact must be set from the full fact set", c.name)
		}
	}
}

// The carve-out: orphaned kinds shadowing BLOCKED-class facts stay
// override-eligible, but the flag says hardened confirm, and the hint never
// pretends the override is unguarded.
func TestOrphanedCarveOut(t *testing.T) {
	now := time.Now()
	in := Input{
		Kind:         classify.KindGitWorktreeOrphaned,
		LastActivity: daysAgo(now, 30),
		Git:          nil, // orphaned worktrees have no readable git facts
		Thresholds:   thresholds(),
		Now:          now,
	}
	v := Decide(in)
	if v.Verdict != Manual || v.Code != "orphaned-worktree" || !v.OrphanedCarveOut {
		t.Fatalf("orphaned: %+v", v)
	}
	if !strings.Contains(v.Hint, "hardened confirm") {
		t.Fatalf("hint must name the hardened confirm: %q", v.Hint)
	}
}

// Ignorance rows: unread state must land MANUAL and can never be override
// eligible (the class maps say so; the test pins the rows themselves).
func TestIgnoranceRows(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		mut  func(*Input)
		code string
	}{
		{"state-unreadable", func(i *Input) { i.Git.StateUnreadable = true; i.Git.Why = "corrupt" }, "state-unreadable"},
		{"facts-unavailable", func(i *Input) { i.Git.FactsUnavailable = true; i.Git.Why = "timeout" }, "facts-unavailable"},
		{"remote-stale", func(i *Input) { i.Git.RemoteStale = true }, "remote-stale"},
		{"gh-unavailable", func(i *Input) { i.PRHeads = &ghx.PRHeads{Unavailable: true} }, "gh-unavailable"},
		{"partial-walk", func(i *Input) { i.SizePartial = true }, "state-unreadable"},
	}
	for _, c := range cases {
		in := gitInput(now)
		c.mut(&in)
		v := Decide(in)
		if v.Verdict != Manual || v.Code != c.code {
			t.Errorf("%s: %s/%s, want MANUAL/%s", c.name, v.Verdict, v.Code, c.code)
		}
		if !ignoranceClass[c.code] {
			t.Errorf("%s: code must be ignorance-class", c.code)
		}
	}
}

func TestJudgmentRows(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		mut  func(*Input)
		code string
	}{
		{"ignored-content", func(i *Input) { i.Git.Ignored = 7; i.Git.IgnoredB = 1 << 20 }, "ignored-content"},
		{"nested-repositories", func(i *Input) { i.NestedVCS = []string{"vendor/x/.git"} }, "nested-repositories"},
		{"parent-of-live-children", func(i *Input) { i.Git.Children = []string{`C:\wt\child`} }, "parent-of-live-children"},
	}
	for _, c := range cases {
		in := gitInput(now)
		c.mut(&in)
		v := Decide(in)
		if v.Verdict != Manual || v.Code != c.code {
			t.Errorf("%s: %s/%s, want MANUAL/%s", c.name, v.Verdict, v.Code, c.code)
		}
		if !judgmentClass[c.code] {
			t.Errorf("%s: code must be judgment-class", c.code)
		}
	}
}

// The shadowing test: a judgment row displaying while a BLOCKED-class fact
// hides behind it must (a) still show the judgment row, (b) carry the
// blocked fact in the hint, (c) have BlockedClassFact set so widening gates
// refuse it. The canonical case: a nested clone is untracked content (dirty)
// inside a dir that displays nested-repositories.
func TestShadowedJudgmentCarriesBlockedFact(t *testing.T) {
	now := time.Now()
	in := gitInput(now)
	in.NestedVCS = []string{"vendor/x/.git"}
	in.Git.Dirty = 3 // the nested clone itself is untracked content
	v := Decide(in)
	if v.Code != "nested-repositories" {
		t.Fatalf("displayed row = %s, want nested-repositories", v.Code)
	}
	if v.BlockedClassFact == "" {
		t.Fatal("shadowed dirty must set BlockedClassFact")
	}
	if !strings.Contains(v.Hint, "resolve that first") {
		t.Fatalf("hint must name the blocking fact: %q", v.Hint)
	}
}

func TestCleanPushedSafe(t *testing.T) {
	now := time.Now()
	v := Decide(gitInput(now))
	if v.Verdict != Safe || v.Code != "clean-pushed" {
		t.Fatalf("clean+pushed: %s/%s", v.Verdict, v.Code)
	}
	if v.BlockedClassFact != "" {
		t.Fatal("clean repo must not carry a blocked fact")
	}
	// Fresh FETCH_HEAD but no gh this run: SAFE is unreachable (ignorance).
	in := gitInput(now)
	in.PRHeads = nil
	if v := Decide(in); v.Verdict == Safe {
		t.Fatal("SAFE without the open-PR fact is a cardinal-rule violation")
	}
}

func TestLineageGroups(t *testing.T) {
	entries := []LineageEntry{
		{Path: `C:\a`, Origin: "deblasis/wintty", Unpushed: 2286},
		{Path: `C:\b`, Origin: "deblasis/wintty", Unpushed: 2286},
		{Path: `C:\c`, Origin: "deblasis/wintty", Unpushed: 12},
		{Path: `C:\d`, Origin: "deblasis/other", Unpushed: 2286},
	}
	groups := LineageGroups(entries, 100)
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1 (a+b share origin+count)", len(groups))
	}
	if len(groups[0].Members) != 2 || groups[0].Count != 2286 {
		t.Fatalf("group = %+v", groups[0])
	}
}

// Matrix completeness: every fixture yields exactly one verdict with a
// non-empty machine code  -  an undefined fall-through is a spec violation.
func TestMatrixCompleteness(t *testing.T) {
	now := time.Now()
	inputs := []Input{scratchInput(now), gitInput(now)}
	for _, kind := range []classify.Kind{classify.KindScratch, classify.KindGitRepo, classify.KindGitWorktree, classify.KindGitWorktreeOrphaned, classify.KindJJRepo, classify.KindJJWorkspace, classify.KindJJWorkspaceOrphaned, classify.KindUnknown} {
		in := gitInput(now)
		in.Kind = kind
		inputs = append(inputs, in)
	}
	// Variations that must still produce a row. Guards keep combinations
	// compatible (a nil Git must not be dereferenced by a later mutation).
	mutations := []func(*Input){
		func(i *Input) { i.Git = nil },
		func(i *Input) { i.JJ = nil },
		func(i *Input) { i.PRHeads = nil },
		func(i *Input) { i.LastActivity = now },
		func(i *Input) { i.LastActivity = time.Time{} },
		func(i *Input) {
			if i.Git != nil {
				i.Git.Dirty = 1
				i.Git.Unpushed = 1
				i.Git.NoRemote = true
			}
		},
	}
	for _, base := range inputs {
		for _, m := range mutations {
			in := base
			m(&in)
			v := Decide(in)
			if v.Verdict == "" || v.Code == "" {
				t.Fatalf("undefined verdict for %+v", in)
			}
			switch v.Verdict {
			case Safe, Blocked, Manual, Active, Keep:
			default:
				t.Fatalf("unknown verdict %q", v.Verdict)
			}
		}
	}
}

// Integration: a real clean+pushed repo end to end through gitx + classify +
// verdict, proving the packages compose into the SAFE the whole tool stands
// on.
func TestIntegrationCleanPushedRepo(t *testing.T) {
	now := time.Now()
	base := t.TempDir()
	dir := filepath.Join(base, "repo")
	remote := filepath.Join(base, "remote.git")
	for _, d := range []string{dir, remote} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	g := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	g("init", "-q", "-b", "main")
	g("-C", remote, "init", "-q", "--bare", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	g("add", "-A")
	g("commit", "-q", "-m", "one")
	g("remote", "add", "origin", remote)
	g("push", "-q", "-u", "origin", "main")
	g("fetch", "-q")

	gr := gitx.Runner{GitBudget: 30 * time.Second, FetchBudget: 120 * time.Second}
	facts := gr.Facts(dir, now, 72*time.Hour)
	if facts.StateUnreadable || facts.FactsUnavailable {
		t.Fatalf("facts failed: %+v", facts)
	}
	info := classify.Dir(dir)
	in := Input{
		Path:         dir,
		Kind:         info.Kind,
		LastActivity: daysAgo(now, 5),
		Git:          &facts,
		PRHeads:      cleanPR(),
		RemoteSlugs:  []string{"local/remote"},
		Thresholds:   thresholds(),
		Now:          now,
	}
	v := Decide(in)
	if v.Verdict != Safe {
		t.Fatalf("integration verdict = %s/%s (%s), want SAFE", v.Verdict, v.Code, v.Reason)
	}
}
