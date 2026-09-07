package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// scanFixture builds a root with one pushed-then-dirtied repo and one aged
// scratch dir, plus a state dir whose config points at the root.
func scanFixture(t *testing.T) (root, stateDir string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	stateDir = filepath.Join(base, "state")
	for _, d := range []string{filepath.Join(root, "repo"), filepath.Join(root, "scratch-old"), stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	g := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	remote := filepath.Join(base, "remote.git")
	if err := os.MkdirAll(remote, 0o755); err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(root, "repo")
	g(repo, "init", "-q", "-b", "main")
	g(remote, "init", "-q", "--bare", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	g(repo, "add", "-A")
	g(repo, "commit", "-q", "-m", "one")
	g(repo, "remote", "add", "origin", remote)
	g(repo, "push", "-q", "-u", "origin", "main")
	g(repo, "fetch", "-q")
	if err := os.WriteFile(filepath.Join(repo, "wip.txt"), []byte("dirty"), 0o644); err != nil {
		t.Fatal(err)
	}

	old := filepath.Join(root, "scratch-old")
	if err := os.WriteFile(filepath.Join(old, "junk"), []byte("j"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Age the dir AND its file: the dir mtime is the activity floor.
	past := time.Now().AddDate(0, 0, -40)
	if err := os.Chtimes(filepath.Join(old, "junk"), past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}

	cfg := `{
  "roots": ["` + filepath.ToSlash(root) + `"],
  "protect": [],
  "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21, "remote-stale-hours": 72, "quarantine-cap-gb": 2, "quarantine-retention-days": 30, "quarantine-margin": 2.5, "min-free-mb": 256, "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"},
  "gh": false,
  "jj": true
}`
	if err := os.WriteFile(filepath.Join(stateDir, "config.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REAP_DIR", stateDir)
	return root, stateDir
}

func TestScanJSONSchemaAndVerdicts(t *testing.T) {
	_, _ = scanFixture(t)

	var out bytes.Buffer
	code := cmdScan([]string{"--json", "--no-gh"}, &out, &bytes.Buffer{})
	if code != ExitOK {
		t.Fatalf("scan exit = %d, want 0 (scan is a report, not a gate)", code)
	}
	var rep struct {
		Entries []struct {
			Path       string `json:"path"`
			Verdict    string `json:"verdict"`
			ReasonCode string `json:"reasonCode"`
		} `json:"entries"`
		Totals struct {
			Sizes    string `json:"sizes"`
			ByReason []struct {
				Code string `json:"code"`
			} `json:"byReason"`
		} `json:"totals"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("scan --json unparseable: %v\n%s", err, out.String())
	}
	byPath := map[string]string{}
	codes := map[string]string{}
	for _, e := range rep.Entries {
		byPath[filepath.Base(e.Path)] = e.Verdict
		codes[filepath.Base(e.Path)] = e.ReasonCode
	}
	// repo: dirty wip.txt written moments ago -> ACTIVE: the active(<48h)
	// row outranks the dirty row in the spec's matrix (a freshly touched dir
	// has nothing to decide yet; the BLOCKED queue picks it up on a later
	// scan). The dirty->BLOCKED pin lives in the verdict package tests.
	if byPath["repo"] != "ACTIVE" || codes["repo"] != "active" {
		t.Fatalf("repo = %s/%s, want ACTIVE/active", byPath["repo"], codes["repo"])
	}
	if byPath["scratch-old"] != "SAFE" || codes["scratch-old"] != "scratch-idle" {
		t.Fatalf("scratch-old = %s/%s, want SAFE/scratch-idle", byPath["scratch-old"], codes["scratch-old"])
	}
	if rep.Totals.Sizes != "logical" {
		t.Fatalf("sizes = %q, want logical", rep.Totals.Sizes)
	}
	if len(rep.Totals.ByReason) == 0 {
		t.Fatal("byReason breakdown must be present")
	}
}

func TestScanTableSections(t *testing.T) {
	_, _ = scanFixture(t)
	var out bytes.Buffer
	if code := cmdScan([]string{"--no-gh"}, &out, &bytes.Buffer{}); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	s := out.String()
	for _, want := range []string{"ACTIVE", "SAFE", "sizes are logical"} {
		if !strings.Contains(s, want) {
			t.Errorf("table missing %q", want)
		}
	}
	if !strings.Contains(s, "scratch idle") {
		t.Error("table must show the scratch dir's reason (prose form)")
	}
}

func TestScanRootsNarrowRefusesUnconfigured(t *testing.T) {
	root, _ := scanFixture(t)
	var out bytes.Buffer
	code := cmdScan([]string{"--roots", `C:\definitely\not\configured`, "--no-gh"}, &out, &bytes.Buffer{})
	if code != ExitUsage {
		t.Fatalf("unconfigured root must be a usage error, got %d", code)
	}
	if code := cmdScan([]string{"--roots", root, "--no-gh"}, &bytes.Buffer{}, &bytes.Buffer{}); code != ExitOK {
		t.Fatalf("configured root narrowed: exit %d", code)
	}
}

// The round-1 panel's live-proven blocker, pinned end to end: a junction
// child of a configured root must verdict KEEP/protected, never a verdict
// computed through the link (it verdicted SAFE/scratch-idle with a
// 106751-day age before the IsReparse wiring existed).
func TestScanJunctionCandidateKeeps(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction test is Windows-specific")
	}
	root, _ := scanFixture(t)
	target := filepath.Join(filepath.Dir(root), "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	ps := `New-Item -ItemType Junction -Path '` + filepath.Join(root, "link") + `' -Target '` + target + `' | Out-Null`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", ps)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot create junction: %v %s", err, out)
	}

	var out bytes.Buffer
	if code := cmdScan([]string{"--json", "--no-gh"}, &out, &bytes.Buffer{}); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	var rep struct {
		Entries []struct {
			Path       string `json:"path"`
			Verdict    string `json:"verdict"`
			ReasonCode string `json:"reasonCode"`
			AgeDays    int    `json:"ageDays"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	for _, e := range rep.Entries {
		if filepath.Base(e.Path) == "link" {
			if e.Verdict != "KEEP" || e.ReasonCode != "protected" {
				t.Fatalf("junction candidate = %s/%s, want KEEP/protected", e.Verdict, e.ReasonCode)
			}
			return
		}
	}
	t.Fatal("junction candidate missing from scan")
}

// Missing tool degrades to ignorance, never the "report as bug" fallback:
// with git absent from PATH, a git repo past the active window must verdict
// MANUAL facts-unavailable (a fresh repo verdicts ACTIVE first  -  row 3
// outranks degradation, which is safe, just not what this test isolates).
func TestScanGitMissingDegradesToFactsUnavailable(t *testing.T) {
	root, _ := scanFixture(t)
	// Age the repo past the 48h window so the active row cannot shadow:
	// every FILE under it (the walk's activity is max file mtime, so aging
	// the dir alone leaves fresh files in charge).
	past := time.Now().AddDate(0, 0, -3)
	repo := filepath.Join(root, "repo")
	filepath.WalkDir(repo, func(p string, d os.DirEntry, err error) error {
		if err == nil {
			os.Chtimes(p, past, past)
		}
		return nil
	})
	empty := t.TempDir() // a PATH with no git

	var out bytes.Buffer
	var stderr bytes.Buffer
	// cmdScan resolves gitx.Available() internally; simulate absence by
	// pointing PATH at an empty dir through the environment the test process
	// already fixed. Since cmdScan caches nothing, run with PATH stripped.
	old := os.Getenv("PATH")
	t.Setenv("PATH", empty)
	defer t.Setenv("PATH", old)
	code := cmdScan([]string{"--json", "--no-gh"}, &out, &stderr)
	_ = code
	var rep struct {
		Entries []struct {
			Path       string `json:"path"`
			Verdict    string `json:"verdict"`
			ReasonCode string `json:"reasonCode"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	for _, e := range rep.Entries {
		if filepath.Base(e.Path) == "repo" {
			if e.Verdict != "MANUAL" || e.ReasonCode != "facts-unavailable" {
				t.Fatalf("repo with git missing = %s/%s, want MANUAL/facts-unavailable", e.Verdict, e.ReasonCode)
			}
			return
		}
	}
	t.Fatalf("repo entry missing under stripped PATH:\n%s", out.String())
}
