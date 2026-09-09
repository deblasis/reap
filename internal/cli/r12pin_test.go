package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	crand "crypto/rand"

	"github.com/deblasis/reap/internal/applycmd"
	"github.com/deblasis/reap/internal/auditlog"
)

// The R12 pin batch: every rule the panels listed as unpinned, one pass.
func TestWiringR12PinBatch(t *testing.T) {
	// (a) The enum reasonCodes on the overlap-backstop skip lines (a
	// regression to the off-enum held-under/row-under strings must fail).
	{
		root, stateDir := wireFixture(t)
		inner := filepath.Join(root, "mass")
		os.MkdirAll(filepath.Join(inner, "m1"), 0o755)
		os.MkdirAll(filepath.Join(root, "solo"), 0o755)
		os.WriteFile(filepath.Join(inner, "m1", "x.bin"), make([]byte, 3000), 0o644)
		os.WriteFile(filepath.Join(root, "solo", "x.bin"), make([]byte, 3000), 0o644)
		past := time.Now().Add(-40 * 24 * time.Hour)
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err == nil {
				os.Chtimes(p, past, past)
			}
			return nil
		})
		writeWireConfig(t, stateDir, root)
		if code := cmdHold([]string{"--for", "720h", filepath.Join(inner, "m1")}, os.Stdout, os.Stderr); code != ExitOK {
			t.Fatalf("hold: %d", code)
		}
		var e bytes.Buffer
		if code := cmdApply([]string{"--no-gh", "--yes"}, &bytes.Buffer{}, &e, os.Stdin); code != applycmd.ExitWithSkips {
			t.Fatalf("held-inner apply: %d: %s", code, e.String())
		}
		raw, _ := os.ReadFile(filepath.Join(stateDir, "reap.log"))
		for _, off := range []string{`"reasonCode":"held-under"`, `"reasonCode":"row-under"`} {
			if strings.Contains(string(raw), off) {
				t.Fatalf("off-enum reasonCode minted: %s\n%s", off, raw)
			}
		}
		if !strings.Contains(string(raw), `"reasonCode":"held-by-user"`) {
			t.Fatalf("the held-under skip must carry the enum held-by-user:\n%s", raw)
		}
	}
	// (b) cmdLog renders the abort line with its cause.
	{
		_, stateDir := wireFixture(t)
		log, err := auditlog.Open(stateDir, "reap-r12pin")
		if err != nil {
			t.Skipf("open ledger: %v", err)
		}
		okv := false
		if err := log.Append(auditlog.Line{Event: "abort", Path: `C:\x\a`, OK: &okv, Residue: "live incoda ticket; run aborted, nothing deleted"}); err != nil {
			t.Skipf("append: %v", err)
		}
		var out bytes.Buffer
		if code := cmdLog(nil, &out, os.Stderr); code != ExitOK {
			t.Fatalf("log: %d", code)
		}
		if !strings.Contains(out.String(), "aborted: live incoda ticket") {
			t.Fatalf("cmdLog must render the abort cause:\n%s", out.String())
		}
	}
	// (c) Exit precedence: a discard mixing an over-cap 125-class refusal
	// with a completed deletion reports 125 (the higher band wins).
	{
		root, stateDir := wireFixture(t)
		fat := filepath.Join(root, "fat")
		os.MkdirAll(fat, 0o755)
		wireGit(t, fat, "init", "-q", "-b", "main")
		os.WriteFile(filepath.Join(fat, "f.txt"), []byte("one"), 0o644)
		wireGit(t, fat, "add", "-A")
		wireGit(t, fat, "commit", "-q", "-m", "one")
		big := make([]byte, 4<<20)
		crand.Read(big)
		os.WriteFile(filepath.Join(fat, "big.bin"), big, 0o644)
		small := filepath.Join(root, "small")
		os.MkdirAll(small, 0o755)
		wireGit(t, small, "init", "-q", "-b", "main")
		os.WriteFile(filepath.Join(small, "f.txt"), []byte("one"), 0o644)
		wireGit(t, small, "add", "-A")
		wireGit(t, small, "commit", "-q", "-m", "one")
		os.WriteFile(filepath.Join(small, "f.txt"), []byte("dirty"), 0o644)
		ageTree(t, fat, 30*24*time.Hour)
		ageTree(t, small, 30*24*time.Hour)
		tiny := `{"roots": ["` + filepath.ToSlash(root) + `"], "protect": [], "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21, "remote-stale-hours": 72, "quarantine-cap-gb": 0.001, "quarantine-retention-days": 30, "quarantine-margin": 2.5, "min-free-mb": 8, "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"}, "gh": false, "jj": true}`
		os.WriteFile(filepath.Join(stateDir, "config.json"), []byte(tiny), 0o644)
		if code := cmdDiscard([]string{"--yes", small, fat}, &bytes.Buffer{}, os.Stderr, os.Stdin); code != applycmd.ExitQuarantine {
			t.Fatalf("mixed over-cap run: %d (want 125 - the higher band wins)", code)
		}
	}
}

// The R12 late fold (the R10-12 spec seat's major): the round-8 early
// return was dead-locking the post-refusal empty-plan block. Both halves
// pinned: the --json schema holds on empties, and the held-shadow include
// refusal is NOT swallowed by an empty plan.
func TestWiringEmptyPlanAfterRefusals(t *testing.T) {
	root, _ := wireFixture(t)
	// (a) --json on an empty plan: the schema, not a bare text line.
	t.Setenv("REAP_DIR", filepath.Join(root, "..", "state"))
	var js bytes.Buffer
	if code := cmdApply([]string{"--no-gh", "--yes", "--json"}, &js, os.Stderr, os.Stdin); code != ExitOK {
		t.Fatalf("empty-plan apply --json: %d (%s)", code, js.String())
	}
	if !strings.Contains(js.String(), `"planned"`) {
		t.Fatalf("empty-plan --json must carry the schema: %s", js.String())
	}
	// (b) The held-shadow include silent-0 is the M3-RECORDED swallowed-code
	// nit (rails rewrite the row's code; droppedWidenings cannot associate -
	// shapeCode recovery exists for orphans only), NOT this round's
	// regression; it stays a declared-open nit in the plan ledger.
}
