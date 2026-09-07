//go:build windows

package cli

import (
	"testing"

	"golang.org/x/sys/windows"
)

// holdNoDelete opens a file WITHOUT FILE_SHARE_DELETE, so os.RemoveAll
// cannot remove it (the prune-failure fixture; Go's own opens share
// delete, POSIX-style, and hold nothing).
func holdNoDelete(t *testing.T, path string) (*winHold, error) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, cerr := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if cerr != nil {
		return nil, cerr
	}
	return &winHold{h: h}, nil
}

type winHold struct{ h windows.Handle }

func (w *winHold) Close() error { return windows.CloseHandle(w.h) }
