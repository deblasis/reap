package cli

import (
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
	if dir, err := os.MkdirTemp("", "reap-no-rail"); err == nil {
		defer os.RemoveAll(dir)
		os.Setenv("INCODA_DIR", filepath.Join(dir, "no-rail"))
	}
	os.Exit(m.Run())
}
