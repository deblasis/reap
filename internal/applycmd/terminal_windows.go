//go:build windows

package applycmd

import (
	"os"

	"golang.org/x/sys/windows"
)

func isTerminalFd(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}
