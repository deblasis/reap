package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The M3 wiring layer through the command functions: discard eligibility,
// quarantine-then-delete, ledger shape, and the log/quarantine/doctor
// surfaces. Same discipline as M2's wiring tests — this is the layer where
// inert dispositions live when untested.

func discardFixture(t *testing.T) (root, stateDir, blockedDir string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	stateDir = filepath.Join(base, "state")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A BLOCKED repo: dirty tracked file, aged past the tripwire.
	blockedDir = filepath.Join(root, "wip")
	if err := os.MkdirAll(blockedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	g := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", blockedDir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GITIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	g("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(blockedDir, "f.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	g("add", "-A")
	g("commit", "-q", "-m", "one")
	if err := os.WriteFile(filepath.Join(blockedDir, "f.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blockedDir, "precious-untracked.txt"), []byte("ONLY COPY"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().AddDate(0, 0, -40)
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			os.Chtimes(p, past, past)
		}
		return nil
	})
	writeWireConfig(t, stateDir, root)
	return root, stateDir, blockedDir
}

// Discard on a BLOCKED dir: quarantines (manifest + capture ref), deletes,
// and the ledger carries quarantinePath + a manifest with the untracked
// file named.
func TestWiringDiscardQuarantinesAndDeletes(t *testing.T) {
	_, stateDir, blocked := discardFixture(t)
	var out bytes2
	code := cmdDiscard([]string{"--yes", blocked}, &out, os.Stderr, os.Stdin)
	if code != ExitOK {
		t.Fatalf("discard: %d (%s)", code, out.String())
	}
	if _, err := os.Stat(blocked); !os.IsNotExist(err) {
		t.Fatal("BLOCKED dir survived discard")
	}
	// Ledger: intent -> result with quarantinePath non-null and the manifest
	// naming the untracked file.
	raw, err := os.ReadFile(filepath.Join(stateDir, "reap.log"))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var probe map[string]any
		if json.Unmarshal([]byte(line), &probe) == nil && probe["event"] == "result" {
			result = probe
		}
	}
	if result == nil {
		t.Fatal("no result line in reap.log")
	}
	if result["quarantinePath"] == nil {
		t.Fatalf("quarantinePath must be non-null on a discard result: %v", result["quarantinePath"])
	}
	// The manifest names the untracked only-copy file.
	if mb, ok := result["manifest"].(string); ok {
		if !strings.Contains(mb, "precious-untracked.txt") {
			// manifest is base64 in the ledger; decode-tolerant check.
			dec, _ := base64Decode(mb)
			if !strings.Contains(dec, "precious-untracked.txt") {
				t.Fatalf("manifest missing the untracked file: %q", dec)
			}
		}
	} else {
		t.Fatal("result line missing manifest")
	}
	// The quarantine session dir exists with a manifest.
	if _, err := os.Stat(filepath.Join(stateDir, "quarantine")); err != nil {
		t.Fatal("no quarantine dir")
	}
}

// Discard on a non-BLOCKED dir refuses (skip, dir untouched): the spec's
// "discard is the BLOCKED resolver" input contract.
func TestWiringDiscardRefusesNonBlocked(t *testing.T) {
	root, stateDir := wireFixture(t) // scratch-old is SAFE scratch-idle
	target := filepath.Join(root, "scratch-old")
	var out bytes2
	code := cmdDiscard([]string{"--yes", target}, &out, os.Stderr, os.Stdin)
	if code != applycmd2ExitWithSkips {
		t.Fatalf("non-BLOCKED discard: %d (want 2, skips)", code)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("non-BLOCKED dir was deleted")
	}
	_ = stateDir
}

// --no-quarantine without a TTY: the 121 mechanical backstop.
func TestWiringDiscardNoQuarantineNonTTY(t *testing.T) {
	_, _, blocked := discardFixture(t)
	var out bytes2
	code := cmdDiscard([]string{"--yes", "--no-quarantine", blocked}, &out, os.Stderr, os.Stdin)
	if code != applycmd2ExitNotTTY {
		t.Fatalf("--no-quarantine non-TTY: %d (want 121)", code)
	}
	if _, err := os.Stat(blocked); err != nil {
		t.Fatal("dir deleted despite refusal")
	}
}

// The log command reads the ledger; quarantine list shows sessions; doctor
// prints without dying.
func TestWiringLogQuarantineDoctor(t *testing.T) {
	_, _, blocked := discardFixture(t)
	cmdDiscard([]string{"--yes", blocked}, &bytes2{}, os.Stderr, os.Stdin)

	var out bytes2
	if code := cmdLog(nil, &out, os.Stderr); code != ExitOK {
		t.Fatalf("log: %d", code)
	}
	if !strings.Contains(out.String(), `"event": "intent"`) && !strings.Contains(out.String(), `"event":"intent"`) {
		t.Fatalf("log output missing intent lines:\n%s", out.String())
	}

	out.Reset()
	if code := cmdQuarantine([]string{"list"}, &out, os.Stderr); code != ExitOK {
		t.Fatalf("quarantine list: %d", code)
	}
	if !strings.Contains(out.String(), "mode=bundle") {
		t.Fatalf("quarantine list output: %s", out.String())
	}

	out.Reset()
	if code := cmdDoctor(nil, &out, os.Stderr); code != ExitOK {
		t.Fatalf("doctor: %d", code)
	}
	for _, want := range []string{"state dir:", "quarantine:", "reap.log:", "gh:", "jj:", "stray"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("doctor missing %q", want)
		}
	}
}
