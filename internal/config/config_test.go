package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCanonicalCaseFoldAndSlashes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("case-fold semantics are Windows-only")
	}
	cases := []struct {
		in, want string
	}{
		{`C:\Temp\Foo\`, `c:\temp\foo`},
		{`c:/temp/foo`, `c:\temp\foo`},
		{`\\?\C:\TEMP\Foo`, `c:\temp\foo`},
		{`C:\temp\foo\..\bar`, `c:\temp\bar`},
	}
	for _, c := range cases {
		if got := Canonical(c.in); got != c.want {
			t.Errorf("Canonical(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A hold typed with a trailing slash or mismatched case must still match: the
// failure mode of a silent mismatch is deletion, not an error.
func TestIsUnderComponentBoundary(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("canonical form differs off Windows")
	}
	if !IsUnder(`C:\TEMP\Foo\`, `c:\temp\foo`) {
		t.Error("case/trailing-slash variant must match")
	}
	if IsUnder(`C:\temp\foobar`, `c:\temp\foo`) {
		t.Error("prefix without a component boundary must NOT match (the C:\\temp\\foo covering C:\\temp\\foobar bug)")
	}
}

func TestMatchProtectGlobs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("canonical form differs off Windows")
	}
	globs := []string{`**/OneDrive/**`, `**/.cache/**`, `C:\Users\x\AppData\Local\vigz\**`}
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Users\x\ONEDRIVE\Documents\f.txt`, true}, // case-insensitive
		{`C:\Users\x\.cache\zig-local\h\c`, true},
		{`C:\Users\x\AppData\Local\vigz\local\h`, true},
		{`C:\Users\x\OneDriveBackup\f.txt`, false}, // ** spans separators but the name must match a component
		{`C:\temp\wintty\src\main.zig`, false},
	}
	for _, c := range cases {
		got, err := MatchProtect(c.path, globs)
		if err != nil {
			t.Fatalf("match %q: %v", c.path, err)
		}
		if got != c.want {
			t.Errorf("MatchProtect(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestExpandRootsPercentAndTilde(t *testing.T) {
	t.Setenv("REAP_TEST_VAR", `C:\srv\data`)
	home, _ := os.UserHomeDir()
	got := ExpandRoots([]string{`%REAP_TEST_VAR%`, `~/src`, `C:\plain`})
	want := []string{`C:\srv\data`, filepath.Join(home, "src"), `C:\plain`}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("root[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoadSaveRoundTripAndInvalid(t *testing.T) {
	dir := t.TempDir()

	// Absent config -> defaults, no error.
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("load with absent config: %v", err)
	}
	if cfg.Thresholds.ActiveHours != 48 {
		t.Fatalf("defaults not applied: %+v", cfg.Thresholds)
	}

	cfg.Roots = []string{`C:\temp`}
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(got.Roots) != 1 || got.Roots[0] != `C:\temp` {
		t.Fatalf("round trip lost roots: %v", got.Roots)
	}

	// Invalid JSON is a hard error, never silent defaults: a protect list that
	// failed to parse would delete what it was meant to keep.
	if err := os.WriteFile(ConfigPath(dir), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("invalid config must error, not fall back to defaults")
	}

	// Empty roots refuse: scanning nothing looks healthy and deletes nothing,
	// which is the incoda split-lane failure shape.
	if err := os.WriteFile(ConfigPath(dir), []byte(`{"roots": []}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("empty roots must refuse")
	}

	// A leading UTF-8 BOM (PowerShell 5 Set-Content -Encoding UTF8) is
	// tolerated, not a parse error (round 5 pin of the strip).
	bom := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"roots": ["C:\\bom-ok"]}`)...)
	if err := os.WriteFile(ConfigPath(dir), bom, 0o644); err != nil {
		t.Fatal(err)
	}
	bomCfg, err := Load(dir)
	if err != nil {
		t.Fatalf("BOM'd config must load: %v", err)
	}
	if len(bomCfg.Roots) != 1 || bomCfg.Roots[0] != `C:\bom-ok` {
		t.Fatalf("BOM'd config lost roots: %v", bomCfg.Roots)
	}
}

func TestAtomicWriteLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := AtomicWrite(path, []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != `{"a":1}` {
		t.Fatalf("read back: %q %v", raw, err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if len(e.Name()) > 0 && e.Name()[0] == '.' && e.Name() != "." && e.Name() != ".." {
			if len(e.Name()) >= 9 && e.Name()[:9] == ".reap-tmp" {
				t.Fatalf("temp file left behind: %s", e.Name())
			}
		}
	}
}

func TestBudgetsParse(t *testing.T) {
	git, jj, gh, fetch, err := Default().Thresholds.Budgets()
	if err != nil {
		t.Fatal(err)
	}
	if git != 30_000_000_000 || fetch != 120_000_000_000 || jj != 30_000_000_000 || gh != 15_000_000_000 {
		t.Fatalf("budgets: git=%v jj=%v gh=%v fetch=%v", git, jj, gh, fetch)
	}
}

// A trailing sep+** protect glob covers the DIRECTORY ITSELF as well as its
// tree: "vigz/**" reads as "vigz and everything under it", and a candidate
// that IS vigz must KEEP (found by the M2 applycmd tests: re-verify let a
// protected dir through because the glob only matched strictly-inside paths).
func TestMatchProtectCoversDirItself(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("canonical form differs off Windows")
	}
	globs := []string{`C:\Users\x\AppData\Local\vigz\**`}
	cases := []struct {
		path string
		want bool
	}{
		{`C:\Users\x\AppData\Local\vigz`, true},         // the dir itself
		{`C:\Users\x\AppData\Local\vigz\local\h`, true}, // inside
		{`C:\Users\x\AppData\Local\vigz-backup`, false}, // component boundary
	}
	for _, c := range cases {
		got, err := MatchProtect(c.path, globs)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("MatchProtect(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
