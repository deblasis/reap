//go:build windows

package quarantine

import (
	"testing"

	"golang.org/x/sys/windows"
)

// holdNoShare opens a file WITHOUT FILE_SHARE_DELETE so git add cannot
// read... precisely: git add FAILS on a file it cannot open, which is the
// AddAll-failure injection the unborn-hoist fixture needs.
func holdNoShare(t *testing.T, path string) (*winHold, error) {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// No share modes at all: any other open (git's read) fails.
	h, cerr := windows.CreateFile(p, windows.GENERIC_READ, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if cerr != nil {
		return nil, cerr
	}
	return &winHold{h: h}, nil
}

type winHold struct{ h windows.Handle }

func (w *winHold) Close() error { return windows.CloseHandle(w.h) }
