package walk

import (
	"os/exec"
	"strings"
)

// runPowerShell is a test helper for creating filesystem primitives that need
// the platform shell (junctions). Not used by non-test code.
func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", script)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
