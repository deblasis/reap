package walk

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, path string, size int, mtime time.Time) {
	t.Helper()
	data := make([]byte, size)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func TestEntrySumsSizesAndMaxMtime(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cand")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-72 * time.Hour)
	writeFile(t, filepath.Join(root, "a.bin"), 100, old)
	writeFile(t, filepath.Join(root, "sub", "b.bin"), 50, now.Add(-1*time.Hour))
	// The dir's own mtime is the activity FLOOR (empty-dir fallback): age it
	// so this test pins the file-driven max, not the freshly-created dir.
	if err := os.Chtimes(root, old, old); err != nil {
		t.Fatal(err)
	}

	info := Entry(root, root, now)
	if info.Bytes != 150 || info.Files != 2 {
		t.Fatalf("bytes=%d files=%d, want 150/2", info.Bytes, info.Files)
	}
	wantMax := now.Add(-1 * time.Hour)
	if info.MaxMtime.Sub(wantMax) > time.Second {
		t.Fatalf("MaxMtime=%v, want ~%v", info.MaxMtime, wantMax)
	}
	if info.Partial {
		t.Fatal("clean walk flagged partial")
	}
	if len(info.NestedVCS) != 0 {
		t.Fatalf("unexpected nested VCS markers: %v", info.NestedVCS)
	}
}

// Empty dirs have no file mtimes: the dir's own mtime is their activity.
func TestEntryEmptyDirFallsBackToDirMtime(t *testing.T) {
	base := t.TempDir()
	now := time.Now()
	old := now.Add(-40 * 24 * time.Hour)
	empty := filepath.Join(base, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(empty, old, old); err != nil {
		t.Fatal(err)
	}
	info := Entry(base, empty, now)
	if info.MaxMtime.IsZero() || info.MaxMtime.After(now) {
		t.Fatalf("empty dir activity = %v, want the aged dir mtime", info.MaxMtime)
	}
	if now.Sub(info.MaxMtime) < 39*24*time.Hour {
		t.Fatalf("empty dir activity too fresh: %v", info.MaxMtime)
	}
}

// A future-dated file must be clamped to now (and counted), so clock skew can
// never make a live dir read as never-active and age it into SAFE. `now` is
// captured AFTER the fixture writes: the writes tick the dir's own mtime,
// which the fallback also clamps against `now`, and a pre-write `now` would
// make the fresh dir count as future (that clamp is correct behavior, just
// not what this test isolates).
func TestEntryClampsFutureMtimes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cand")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	writeFile(t, filepath.Join(root, "skewed"), 10, base.Add(48*time.Hour))
	writeFile(t, filepath.Join(root, "normal"), 10, base.Add(-2*time.Hour))
	now := time.Now()

	info := Entry(root, root, now)
	if info.Clamped != 1 {
		t.Fatalf("Clamped=%d, want 1 (only the skewed file)", info.Clamped)
	}
	if info.MaxMtime.After(now) {
		t.Fatalf("MaxMtime %v escaped the clamp", info.MaxMtime)
	}
}

func TestEntryDetectsNestedVCS(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cand")
	nested := filepath.Join(root, "vendor", "clone")
	if err := os.MkdirAll(filepath.Join(nested, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(nested, ".git", "config"), 20, time.Now())

	info := Entry(root, root, time.Now())
	if len(info.NestedVCS) != 1 {
		t.Fatalf("NestedVCS=%v, want the vendored .git", info.NestedVCS)
	}
	// The candidate's OWN .git is not "nested" (depth >= 1 only): a git repo's
	// marker belongs to the candidate itself, not to nested-repositories.
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	info = Entry(root, root, time.Now())
	if len(info.NestedVCS) != 1 {
		t.Fatalf("own .git miscounted as nested: %v", info.NestedVCS)
	}
}

// A submodule's .git is a FILE (gitdir pointer), not a directory: the walk
// must flag it as a nested VCS marker or a superproject with ignore=dirty
// hides the submodule's real state (the reliability seat proved this mints
// SAFE on the parent).
func TestEntryDetectsSubmoduleGitFile(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "vendor", "lib")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, ".git"), []byte("gitdir: ../../.git/modules/lib\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info := Entry(root, root, time.Now())
	found := false
	for _, m := range info.NestedVCS {
		if strings.HasSuffix(filepath.ToSlash(m), "vendor/lib/.git") {
			found = true
		}
	}
	if !found {
		t.Fatalf("submodule .git file not flagged: %v", info.NestedVCS)
	}
	// The candidate's OWN linked .git (depth 0) is still not nested.
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info = Entry(root, root, time.Now())
	for _, m := range info.NestedVCS {
		if m == ".git" {
			t.Fatal("own linked .git must not count as nested")
		}
	}
}

func TestEntryMissingPathIsPartial(t *testing.T) {
	info := Entry(t.TempDir(), filepath.Join(t.TempDir(), "gone"), time.Now())
	if !info.Partial {
		t.Fatal("missing path must be Partial so the verdict can route MANUAL")
	}
}

func TestRootsListsOnlyChildren(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "r1")
	if err := os.MkdirAll(filepath.Join(root, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "loose.txt"), 5, time.Now())

	infos := Roots([]string{root, filepath.Join(base, "missing-root")}, time.Now(), 4)
	var paths []string
	for _, i := range infos {
		paths = append(paths, filepath.Base(i.Path))
	}
	if len(infos) != 3 { // a, b, and the missing root marker
		t.Fatalf("infos=%v", paths)
	}
	// Loose files are not candidates; the missing root is surfaced, not silent.
	for _, i := range infos {
		if i.Path == filepath.Join(base, "missing-root") && !i.Partial {
			t.Fatal("missing root must be surfaced as Partial")
		}
	}
}

// Roots must surface reparse-point candidates WITH the IsReparse flag and
// without walking through the link: the KEEP rail depends on the flag, and
// facts harvested through a junction are evidence about a different path.
func TestRootsSurfacesReparseCandidates(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction test is Windows-specific")
	}
	base := t.TempDir()
	root := filepath.Join(base, "root")
	target := filepath.Join(base, "target")
	for _, d := range []string{root, target, filepath.Join(root, "plain")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(target, "big.bin"), 4096, time.Now())
	ps := `New-Item -ItemType Junction -Path '` + filepath.Join(root, "link") + `' -Target '` + target + `' | Out-Null`
	if out, err := runPowerShell(ps); err != nil {
		t.Skipf("cannot create junction (skipping): %v %s", err, out)
	}

	infos := Roots([]string{root}, time.Now(), 4)
	byName := map[string]DirInfo{}
	for _, i := range infos {
		byName[filepath.Base(i.Path)] = i
	}
	link, ok := byName["link"]
	if !ok {
		t.Fatalf("junction candidate not surfaced: %+v", infos)
	}
	if !link.IsReparse {
		t.Fatal("junction candidate must carry IsReparse=true")
	}
	if link.Bytes != 0 || !link.MaxMtime.IsZero() {
		t.Fatalf("junction candidate must not be walked: %+v", link)
	}
	if plain, ok := byName["plain"]; !ok || plain.IsReparse {
		t.Fatalf("plain dir misflagged: %+v", byName)
	}
}

// Junctions must be skipped, not followed: a junction under the tree can loop
// or escape into protected paths (OneDrive placeholders measured 545 GB). This
// test creates a real junction on Windows, where the rule actually bites.
func TestEntrySkipsJunctions(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction test is Windows-specific")
	}
	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "cand", "link")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "big.bin"), 4096, time.Now())
	ps := `New-Item -ItemType Junction -Path '` + dst + `' -Target '` + src + `' | Out-Null`
	out, err := runPowerShell(ps)
	if err != nil {
		t.Skipf("cannot create junction (skipping): %v %s", err, out)
	}
	writeFile(t, filepath.Join(base, "cand", "own.bin"), 7, time.Now())

	info := Entry(filepath.Join(base, "cand"), filepath.Join(base, "cand"), time.Now())
	if info.Bytes != 7 {
		t.Fatalf("bytes=%d, want 7 (junction target must not be counted)", info.Bytes)
	}
}

// ChildrenMaxMtime's error path fails toward the tripwire (round 12; the
// R7 reliability minor): an unreadable activity set must never read as
// quiet - ok=false so the caller keeps the fresh stamp and skips.
func TestChildrenMaxMtimeFailsTowardTripwire(t *testing.T) {
	if _, ok := ChildrenMaxMtime(filepath.Join(t.TempDir(), "nowhere"), time.Now(), false); ok {
		t.Fatal("a failed read must report ok=false (fail-toward), not quiet")
	}
}
