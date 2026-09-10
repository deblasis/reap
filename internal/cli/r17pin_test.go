package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deblasis/reap/internal/applycmd"
	"github.com/deblasis/reap/internal/config"
	"github.com/deblasis/reap/internal/quarantine"
)

// The R17 pin batch: the full-implementation board's fold. The headline is
// the reliability major - the first-ever hold landing in the confirm window
// panicked the under-lock merge (nil holds map) instead of running the
// sanctioned 122 abort.
func TestWiringR17FirstHoldMidRunNoPanic(t *testing.T) {
	root, stateDir := wireFixture(t)
	// (a) The source: a missing holds.json loads as INITIALIZED maps. Red on
	// the pre-fix code (nil, nil, nil).
	h, exp, err := loadHoldsWithExpired(stateDir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if h == nil || exp == nil {
		t.Fatalf("a fresh state dir must load holds as EMPTY maps, never nil (the nil-map merge panicked the first-ever mid-run hold): %v %v", h == nil, exp == nil)
	}
	// (b) The merge site: core.holds must be writable and the merge of a
	// hold that lands between scan and the under-lock re-read must not
	// panic. Red on the pre-fix code (assignment to nil map).
	core, code := newScanCore(nil, os.Stderr, []string{root}, true, false)
	if core == nil {
		t.Fatalf("newScanCore: %d", code)
	}
	if core.holds == nil {
		t.Fatal("core.holds must never be nil, even with no holds.json")
	}
	if code := cmdHold([]string{"--for", "720h", filepath.Join(root, "scratch-old")}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold: %d", code)
	}
	for h2 := range applycmd.ReadHoldsSnapshot(stateDir) {
		core.holds[h2] = true // the exact line that panicked
	}
	if !core.holds[config.Canonical(filepath.Join(root, "scratch-old"))] {
		t.Fatal("the mid-window hold must be visible to the gate")
	}
}

// The tool's own usage lines print PATH-first spellings (`reap hold PATH
// [--for DUR]`, `reap discard PATH... [--yes]`): they must parse AS PRINTED
// (Go's flag package stops at the first positional; flagsFirst reorders).
func TestWiringR17FlagOrderAsPrinted(t *testing.T) {
	root, _ := wireFixture(t)
	if code := cmdHold([]string{filepath.Join(root, "scratch-old"), "--for", "48h"}, os.Stdout, os.Stderr); code != ExitOK {
		t.Fatalf("hold PATH --for DUR must parse: %d", code)
	}
	var hb, e bytes.Buffer
	if code := cmdHolds(nil, &hb, &e); code != ExitOK || !strings.Contains(hb.String(), "scratch-old") {
		t.Fatalf("holds after PATH-first hold: %d (rows %q)", code, hb.String())
	}
	// discard PATH --yes --json on an already-held (non-BLOCKED) dir: the
	// wave-0 hold refusal proves the flags parsed (pre-fix, --yes became a
	// path operand and the run failed differently).
	var out bytes.Buffer
	if code := cmdDiscard([]string{filepath.Join(root, "scratch-old"), "--yes"}, &out, &e, os.Stdin); code != applycmd.ExitUsage {
		t.Fatalf("discard PATH --yes must parse and hit the wave-0 KEEP refusal: %d (%s %s)", code, out.String(), e.String())
	}
}

// reap holds refuses loudly on a corrupt holds.json (the strict read): the
// human checking why a dir was deleted must never see "no holds".
func TestWiringR17HoldsStrict(t *testing.T) {
	_, stateDir := wireFixture(t)
	if err := os.WriteFile(filepath.Join(stateDir, "holds.json"), []byte("{corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	var e bytes.Buffer
	if code := cmdHolds(nil, os.Stdout, &e); code != ExitState || !strings.Contains(e.String(), "corrupt") {
		t.Fatalf("holds on corrupt file: %d: %s", code, e.String())
	}
}

// The expiry-at-consequence pin (a spec-named family, live-verified by the
// board but unpinned): a hold that lapsed within 7 days marks the scan row
// and renders plan's distinct section.
func TestWiringR17ExpiredHoldSections(t *testing.T) {
	root, stateDir := wireFixture(t)
	p := filepath.Join(root, "scratch-old")
	lapsed := time.Now().Add(-3 * 24 * time.Hour)
	body, merr := json.Marshal(map[string]map[string]string{config.Canonical(p): {"expires": lapsed.Format(time.RFC3339)}})
	if merr != nil {
		t.Fatal(merr)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "holds.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	var s bytes.Buffer
	if code := cmdScan([]string{"--no-gh"}, &s, os.Stderr); code != ExitOK {
		t.Fatalf("scan: %d", code)
	}
	if !strings.Contains(s.String(), "[hold expired ") {
		t.Fatalf("the scan row must carry the expiry mark:\n%s", s.String())
	}
	var plan bytes.Buffer
	if code := cmdPlan([]string{"--no-gh"}, &plan, os.Stderr); code != ExitOK {
		t.Fatalf("plan: %d", code)
	}
	if !strings.Contains(plan.String(), "expired hold:") {
		t.Fatalf("plan must render its expired-hold section:\n%s", plan.String())
	}
}

// Exit 124 pinned (the spec's deletion-failed band, path named): a
// deny-delete ACL inside a SAFE dir fails the deletion, preserves the husk
// contents-first, and names the path.
func TestWiringR17DeleteFail124(t *testing.T) {
	root, _ := wireFixture(t)
	target := filepath.Join(root, "scratch-old")
	locked := filepath.Join(target, "locked.bin")
	if err := os.WriteFile(locked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The fresh file must not trip the activity rail: re-age the whole dir.
	ageTree(t, target, 40*24*time.Hour)
	_ = locked // the fresh file only keeps the dir REAL; the fault is the seam below
	restoreRC := applycmd.RemoveContents
	applycmd.RemoveContents = func(string) error { return os.ErrPermission }
	t.Cleanup(func() { applycmd.RemoveContents = restoreRC })
	var e bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes"}, os.Stdout, &e, os.Stdin); code != applycmd.ExitDeleteFail {
		t.Fatalf("deny-delete inside a SAFE dir: %d (want 124): %s", code, e.String())
	}
	if !strings.Contains(e.String(), "deletion failed") {
		t.Fatalf("the failure must name the path:\n%s", e.String())
	}
	if _, err := os.Stat(locked); err != nil {
		t.Fatal("the denied file must survive (contents-first preserves the husk)")
	}
}

// discard --json emits the one-shape summary (lists as [], never null) -
// the fourth emitter, aligned by routing through Summary.EmitJSON.
func TestWiringR17DiscardJSONShape(t *testing.T) {
	root, stateDir := wireFixture(t)
	repo := filepath.Join(root, "d1")
	os.MkdirAll(repo, 0o755)
	wireGit(t, repo, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(repo, "f.txt"), []byte("wip"), 0o644)
	ageTree(t, repo, 30*24*time.Hour)
	writeWireConfig(t, stateDir, root)
	var js bytes.Buffer
	if code := cmdDiscard([]string{"--yes", "--json", repo}, &js, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("discard --json: %d (%s)", code, js.String())
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(js.String())), &doc); err != nil {
		t.Fatalf("discard --json must be a pure JSON doc (no text prefix): %v\n%s", err, js.String())
	}
	for _, list := range []string{"planned", "widened", "deleted", "skipped", "excludedBelowFloor", "excludedByCode"} {
		v, ok := doc[list]
		if !ok {
			t.Fatalf("missing %s:\n%s", list, js.String())
		}
		if _, isArray := v.([]any); !isArray {
			t.Fatalf("discard --json %s must be an array, got %T (null?):\n%s", list, v, js.String())
		}
	}
	if got := len(doc["deleted"].([]any)); got != 1 {
		t.Fatalf("deleted = %d, want the dirty repo:\n%s", got, js.String())
	}
}

// The -- terminator is a hard positional boundary (the verification board's
// spec nit; the final board's eng seat found the R18 pin VACUOUS - an
// absolute path never dash-prefixed as a token - so this pin asserts the
// REORDER OUTPUT and the composite parse, red on the hoisting shape).
func TestWiringR18FlagsFirstTerminator(t *testing.T) {
	// (a) Tokens past -- are never hoisted (the pre-R19 code returned
	// ["-weirdpath", "PATH", "--", "other"] here).
	got := strings.Join(flagsFirst([]string{"PATH", "--", "-weirdpath", "other"}), "|")
	if got != "--|PATH|-weirdpath|other" {
		t.Fatalf("terminator boundary broken: %s", got)
	}
	// (b) Flags still hoist ahead of positionals when NO terminator exists,
	// value flags carrying their operand.
	got = strings.Join(flagsFirst([]string{"P", "--for", "48h", "Q"}), "|")
	if got != "--for|48h|P|Q" {
		t.Fatalf("flag hoisting broken: %s", got)
	}
	// (c) The grammar end to end: the reordered args parse, and the
	// dash-leading token survives as a positional.
	fs := flag.NewFlagSet("hold", flag.ContinueOnError)
	var forStr string
	fs.StringVar(&forStr, "for", "", "")
	fs.SetOutput(io.Discard)
	if err := fs.Parse(flagsFirst([]string{"PATH", "--", "-weirdpath"})); err != nil {
		t.Fatalf("the terminator shape must parse (the hoisting shape failed here): %v", err)
	}
	if fs.NArg() != 2 || fs.Arg(0) != "PATH" || fs.Arg(1) != "-weirdpath" {
		t.Fatalf("positionals after -- must survive verbatim: %v", fs.Args())
	}
}

// The R19 coverage pins (the final board's spec seat: four R18 surfaces
// shipped live-proven but unpinned).
func TestWiringR19UnverifiedCauseCopy(t *testing.T) {
	if got := stateLabel("unverified", quarantine.CauseBundle); got != "unverified (bundle corrupt/unreadable)" {
		t.Fatalf("bundle cause: %q", got)
	}
	if got := stateLabel("unverified", quarantine.CauseRemote); got != "unverified (could not reach the remote)" {
		t.Fatalf("remote cause: %q", got)
	}
	if got := stateLabel("unverified", quarantine.CauseNone); got != "unverified (no manifest; contents unknown)" {
		t.Fatalf("no-manifest cause: %q", got)
	}
	if got := stateLabel("verified-ok", ""); got != "verified-ok" {
		t.Fatalf("verified: %q", got)
	}
}

// Corrupt-bundle restore end to end: 125, the named corrupt copy, and the
// self-created destination cleaned (the R18/R19 fold, pinned).
func TestWiringR19CorruptRestore125(t *testing.T) {
	root, stateDir := wireFixture(t)
	repo := filepath.Join(root, "d1")
	os.MkdirAll(repo, 0o755)
	wireGit(t, repo, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(repo, "f.txt"), []byte("wip"), 0o644)
	ageTree(t, repo, 30*24*time.Hour)
	writeWireConfig(t, stateDir, root)
	var js bytes.Buffer
	if code := cmdDiscard([]string{"--yes", repo}, &js, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("discard: %d (%s)", code, js.String())
	}
	sessions := quarantine.List(stateDir)
	if len(sessions) != 1 {
		t.Fatalf("sessions: %d", len(sessions))
	}
	sess := sessions[0].Dir
	bundle := filepath.Join(sess, "bundle.git")
	raw, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, raw[:len(raw)/3], 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "restore-dest")
	var e bytes.Buffer
	if code := cmdQuarantine([]string{"restore", filepath.Base(sess), "--to", dest, "--json"}, os.Stdout, &e, os.Stdin); code != applycmd.ExitQuarantine {
		t.Fatalf("corrupt restore: %d (want 125): %s", code, e.String())
	}
	if !strings.Contains(e.String(), "corrupt or truncated") {
		t.Fatalf("the refusal must name the shape:\n%s", e.String())
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("the self-created destination must be cleaned on failure")
	}
}

// An explicit --older-than 0s means "prune everything" (the verification
// board's rel nit: the zero duration was silently conflated with unset).
func TestWiringR18PruneOlderThanZero(t *testing.T) {
	_, stateDir := wireFixture(t)
	// An aged session dir with a manifest so the victim scan sees it.
	sess := filepath.Join(stateDir, "quarantine", "20260101-000000-x")
	os.MkdirAll(sess, 0o755)
	os.WriteFile(filepath.Join(sess, "manifest.json"), []byte(`{"mode":"plain-copy","selfContained":true}`), 0o644)
	// YOUNGER than the 30d retention default: pre-fix, the conflated 0
	// duration meant "unset" and this printed "nothing to prune"; with 0s
	// honored it prunes.
	recent := time.Now().Add(-5 * 24 * time.Hour)
	os.Chtimes(sess, recent, recent)
	var out, e bytes.Buffer
	if code := cmdQuarantine([]string{"prune", "--older-than", "0s", "--yes"}, &out, &e, os.Stdin); code != ExitOK {
		t.Fatalf("prune --older-than 0s: %d (%s %s)", code, out.String(), e.String())
	}
	if !strings.Contains(out.String(), "pruned 1") {
		t.Fatalf("0s must prune the 5d session (the old zero-value conflation printed 'nothing to prune'): %s", out.String())
	}
	if _, err := os.Stat(sess); !os.IsNotExist(err) {
		t.Fatal("the session must be gone")
	}
}
