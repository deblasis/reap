package dedupe

import (
	"os"
	"path/filepath"
	"testing"
)

// The deletion-set pass: two dirs hardlinking one file — logical counts
// the file twice, expected counts the physical content once (the zig-lane
// shape the two-number truth exists for). Skipped on filesystems that do
// not expose classic file indexes (ReFS/Dev Drive: the pass degrades to
// the logical upper bound there, by design).
func TestCounterHardlinkCountedOnce(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	src := filepath.Join(a, "shared.bin")
	if err := os.WriteFile(src, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(src, filepath.Join(b, "shared.bin")); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if err := os.WriteFile(filepath.Join(a, "solo.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Capability probe: some volumes (ReFS/Dev Drive) do not expose
	// classic file indexes; the pass degrades to logical there.
	if !IndexesAvailable(src) {
		t.Skip("filesystem does not expose file indexes (ReFS/Dev Drive); pass degrades to logical")
	}
	c := NewCounter(1000)
	c.Add(a)
	c.Add(b)
	if c.Logical <= c.Expected {
		t.Fatalf("hardlink not detected: logical=%d expected=%d", c.Logical, c.Expected)
	}
	if c.Expected < 1<<20 {
		t.Fatalf("expected must count the shared content once: %d", c.Expected)
	}
	if c.Over() {
		t.Fatal("small set must not trip the cap")
	}
}
