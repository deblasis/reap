package walk

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestCacheRoundTripAndInvalidation(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "cand")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	writeFile(t, filepath.Join(root, "x"), 42, now)
	info := Entry(root, root, now)
	c.Record(root, info, now)

	if got, ok := c.Size(root); !ok || got != 42 {
		t.Fatalf("Size=%d ok=%v, want 42/true", got, ok)
	}

	// Deep write to an EXISTING file: dir mtime and child count unchanged, so
	// the cheap keys still hit — which is exactly why the TTL exists. Shrink
	// the TTL to prove the entry expires rather than trusting forever.
	writeFile(t, filepath.Join(root, "x"), 4200, now)
	c.ttl = -1 // force expiry
	if _, ok := c.Size(root); ok {
		t.Fatal("expired entry must miss")
	}

	// A new child changes the count and must invalidate immediately.
	c2, _ := LoadCache(dir)
	c2.Record(root, Entry(root, root, now), now)
	writeFile(t, filepath.Join(root, "y"), 1, now)
	c2.ttl = time.Hour
	if _, ok := c2.Size(root); ok {
		t.Fatal("child-count change must invalidate")
	}

	// Persist from a FRESH walk of the current state, then reload: the point
	// under test is durability of valid entries, not resurrection of the
	// invalidated one.
	c2.Record(root, Entry(root, root, now), now)
	if err := c2.Save(); err != nil {
		t.Fatal(err)
	}
	c3, err := LoadCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c3.Size(filepath.Join(dir, "cand")); !ok {
		t.Fatal("persisted cache lost a fresh entry")
	}

	// Partial walks are never recorded: a lower bound must not become cached
	// truth. Fresh state dir so the persisted entry above cannot mask it.
	c4, _ := LoadCache(t.TempDir())
	c4.Record(root, DirInfo{Path: root, Bytes: 1, Partial: true}, now)
	if _, ok := c4.Size(root); ok {
		t.Fatal("partial walk must not be cached")
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
