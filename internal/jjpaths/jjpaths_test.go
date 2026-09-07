package jjpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The resolver's table: every pointer shape jj writes (or a hand-rolled
// layout can produce), pinned. This package shipped with zero tests in
// round 8 while being the round's centerpiece.
func TestResolveTable(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "myroot")
	main := filepath.Join(base, "main") // a bare split-layout repo dir
	ws := filepath.Join(base, "ws")
	for _, d := range []string{filepath.Join(root, ".jj", "repo"), main, filepath.Join(ws, ".jj")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(content string) {
		if err := os.WriteFile(filepath.Join(ws, ".jj", "repo"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name       string
		content    string
		repoDir    string // "" = ok=false shape
		parentRoot string // "" = root-repo shape (ok=true, no parent)
	}{
		{"colocated abs", root + `\.jj\repo`, root + `\.jj\repo`, root},
		{"colocated rel", `..\..\myroot\.jj\repo`, root + `\.jj\repo`, root},
		{"store infix abs", root + `\.jj\repo\store\git`, root + `\.jj\repo\store\git`, root},
		{"bare dir", main, main, main},
		{"dot root", ".", "", ""},
		{"empty", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			write(c.content)
			l, ok := Resolve(ws)
			if c.repoDir == "" && c.parentRoot == "" {
				if !ok || l.ParentRoot != "" {
					t.Fatalf("want root-repo shape, got ok=%v %+v", ok, l)
				}
				return
			}
			if filepath.Clean(l.RepoDir) != filepath.Clean(c.repoDir) {
				t.Fatalf("RepoDir: %q want %q", l.RepoDir, c.repoDir)
			}
			if filepath.Clean(l.ParentRoot) != filepath.Clean(c.parentRoot) {
				t.Fatalf("ParentRoot: %q want %q", l.ParentRoot, c.parentRoot)
			}
		})
	}

	// A pointer naming the workspace itself, with a CASE-VARIANT segment
	// (the fold compare is EqualFold): root repo, not a workspace of itself.
	variant := ws
	if i := strings.LastIndex(filepath.Base(ws), "s"); i >= 0 {
		b := []byte(filepath.Base(ws))
		b[i] = 'S'
		variant = filepath.Join(filepath.Dir(ws), string(b))
	} else {
		variant = strings.ToUpper(ws)
	}
	write(variant)
	if l, ok := Resolve(ws); !ok || l.ParentRoot != "" {
		t.Fatalf("case-variant self-pointer must be root shape, got ok=%v %+v", ok, l)
	}

	// Absent marker: ok=false.
	if err := os.Remove(filepath.Join(ws, ".jj", "repo")); err != nil {
		t.Fatal(err)
	}
	if _, ok := Resolve(ws); ok {
		t.Fatal("absent marker must be ok=false")
	}
}
