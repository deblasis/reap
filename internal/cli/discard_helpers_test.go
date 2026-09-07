package cli

import (
	"bytes"
	"encoding/base64"
	"os/exec"
	"strings"
)

// bytes2 is a alias so the M3 wiring tests read like the M2 ones.
type bytes2 = bytes.Buffer

const (
	applycmd2ExitWithSkips = 2
	applycmd2ExitNotTTY    = 121
)

func base64Decode(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	return string(raw), err
}

// gitFor is shared git plumbing for wiring tests (unused-in-this-file).
func gitFor(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
