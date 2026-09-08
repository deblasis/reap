package incodalog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain makes the whole package hermetic against the machine's live
// incoda rail (round 8; the cli package's twin): every test inherits a
// fresh empty INCODA_DIR. Rail-fixture tests t.Setenv their own, which
// wins for that test and restores to this on cleanup.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "reap-incodalog-no-rail")
	if err != nil {
		fmt.Fprintln(os.Stderr, "incodalog tests: cannot create the hermetic INCODA_DIR:", err)
		os.Exit(1)
	}
	os.Setenv("INCODA_DIR", filepath.Join(dir, "no-rail"))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
