package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain makes the WHOLE cli package hermetic against the machine's live
// incoda rail (round 7; the R5 and R6 gate-reds: a torn ticket or lane
// transition mid-suite reds unrelated tests through the sentinel). Every
// test inherits a fresh empty INCODA_DIR - no rail to be blind about.
// Tests that deliberately build rail fixtures t.Setenv their own, which
// wins for that test and restores to this on cleanup.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "reap-no-rail")
	if err != nil {
		// Hard-fail, never proceed unpinned (the R7 spec seat's nit): an
		// unpinned run reads the machine's live rail.
		fmt.Fprintln(os.Stderr, "reap cli tests: cannot create the hermetic INCODA_DIR:", err)
		os.Exit(1)
	}
	os.Setenv("INCODA_DIR", filepath.Join(dir, "no-rail"))
	code := m.Run()
	os.RemoveAll(dir) // before Exit: a defer would never run (the R7 eng seat)
	os.Exit(code)
}
