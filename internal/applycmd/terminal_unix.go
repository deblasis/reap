//go:build !windows

package applycmd

import (
	"os"
	"os/exec"
)

// isTerminalFd is a VAR for the test seam; see terminal_windows.go.
var isTerminalFd = func(f *os.File) bool {
	// A pipe or redirect differs from a tty; `tty -s` is the portable probe
	// where ioctl plumbing is more surface than the question deserves here.
	c := exec.Command("tty", "-s")
	c.Stdin = f
	return c.Run() == nil
}

// ForceTerminal swaps the terminal probe for tests. Returns a restore func.
func ForceTerminal(tty bool) (restore func()) {
	orig := isTerminalFd
	isTerminalFd = func(*os.File) bool { return tty }
	return func() { isTerminalFd = orig }
}
