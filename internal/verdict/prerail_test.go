package verdict

import (
	"testing"
	"time"

	"github.com/deblasis/reap/internal/classify"
	"github.com/deblasis/reap/internal/gitx"
)

// PreRailCode (round 15; the M3-recorded swallowed-code silent zero): the
// rails outrank the body rows, but the code the row would carry WITHOUT
// them survives the rewrite - the include-refusal association keys on it.
func TestPreRailCode(t *testing.T) {
	now := time.Now()
	dirtyGit := func() *gitx.Facts { return &gitx.Facts{Dirty: 2} }
	base := func() Input {
		return Input{
			Path:       `C:\t\a`,
			Kind:       classify.KindGitRepo,
			GitBackend: true,
			Git:        dirtyGit(),
			Thresholds: thresholds(),
			Now:        now,
		}
	}
	// Unrailed: no stamp (the row IS its own code).
	if v := Decide(base()); v.Code != "dirty-files" || v.PreRailCode != "" {
		t.Fatalf("unrailed: code %q preRail %q, want dirty-files with no stamp", v.Code, v.PreRailCode)
	}
	// Held: the KEEP row carries the body's code.
	in := base()
	in.Held = true
	if v := Decide(in); v.Code != "held-by-user" || v.PreRailCode != "dirty-files" {
		t.Fatalf("held: code %q preRail %q, want held-by-user/dirty-files", v.Code, v.PreRailCode)
	}
	// Protected: same.
	in = base()
	in.Protected = true
	if v := Decide(in); v.Code != "protected" || v.PreRailCode != "dirty-files" {
		t.Fatalf("protected: code %q preRail %q, want protected/dirty-files", v.Code, v.PreRailCode)
	}
	// incoda-live: the ACTIVE rail stamps too.
	in = base()
	in.IncodaLive = true
	if v := Decide(in); v.Verdict != Active || v.Code != "incoda-live" || v.PreRailCode != "dirty-files" {
		t.Fatalf("incoda-live: %s/%q preRail %q, want ACTIVE/incoda-live/dirty-files", v.Verdict, v.Code, v.PreRailCode)
	}
	// Fresh activity: the ACTIVE rail stamps the would-be BLOCKED code
	// (the fresh-but-dirty shape: include association must survive).
	in = base()
	in.LastActivity = now.Add(-1 * time.Hour)
	if v := Decide(in); v.Verdict != Active || v.Code != "active" || v.PreRailCode != "dirty-files" {
		t.Fatalf("fresh: %s/%q preRail %q, want ACTIVE/active/dirty-files", v.Verdict, v.Code, v.PreRailCode)
	}
	// A fresh ORPHAN carries its carve-out code under the activity rail
	// (the shapeCode class the old recovery existed for).
	orphan := Input{
		Path:         `C:\t\w`,
		Kind:         classify.KindGitWorktreeOrphaned,
		LastActivity: now.Add(-1 * time.Hour),
		Thresholds:   thresholds(),
		Now:          now,
	}
	if v := Decide(orphan); v.Code != "active" || v.PreRailCode != "orphaned-worktree" {
		t.Fatalf("fresh orphan: code %q preRail %q, want active/orphaned-worktree", v.Code, v.PreRailCode)
	}
	// The rail rows keep their OWN shapes: a held scratch dir with no facts
	// stamps the scratch tier code, not a phantom.
	held := Input{Kind: classify.KindScratch, Held: true,
		LastActivity: daysAgo(now, 30), Thresholds: thresholds(), Now: now}
	if v := Decide(held); v.Code != "held-by-user" || v.PreRailCode != "scratch-idle" {
		t.Fatalf("held scratch: code %q preRail %q, want held-by-user/scratch-idle", v.Code, v.PreRailCode)
	}
}
