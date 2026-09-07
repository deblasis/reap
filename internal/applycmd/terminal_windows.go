//go:build windows

package applycmd

import (
	"os"

	"golang.org/x/sys/windows"
)

// isTerminalFd is a VAR (not a func): the TTY-gated choreography — the
// carve-out's hardened confirm, --no-quarantine — is otherwise untestable
// from `go test`, where stdin/stdout are never consoles and only the
// non-TTY branch ever executes (the round-5 reliability finding: ~80 lines
// of the tool's most dangerous surface with zero automated coverage).
var isTerminalFd = func(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

// ForceTerminal swaps the terminal probe for tests (true = every check
// passes as a TTY; false = none do). Returns a restore func.
func ForceTerminal(tty bool) (restore func()) {
	orig := isTerminalFd
	isTerminalFd = func(*os.File) bool { return tty }
	return func() { isTerminalFd = orig }
}
