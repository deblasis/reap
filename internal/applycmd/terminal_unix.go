//go:build !windows

package applycmd

import (
	"os"
	"os/exec"
)

func isTerminalFd(f *os.File) bool {
	// A pipe or redirect differs from a tty; `tty -s` is the portable probe
	// where ioctl plumbing is more surface than the question deserves here.
	c := exec.Command("tty", "-s")
	c.Stdin = f
	return c.Run() == nil
}
