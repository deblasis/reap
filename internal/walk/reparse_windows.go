//go:build windows

package walk

import (
	"os"

	"golang.org/x/sys/windows"
)

// IsReparse reports whether path is a reparse point (junction, symlink, mount
// point). Go's Lstat does flag symlinks, but junction detection has varied
// across Go versions, and reap's never-cross rule must hold for every reparse
// flavor, so the attribute is read straight from the filesystem.
//
// d may be nil, in which case the path is stat'ed lazily via attributes only.
func IsReparse(path string, d os.DirEntry) (bool, error) {
	if d != nil {
		if d.Type()&os.ModeSymlink != 0 {
			return true, nil
		}
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return false, err
	}
	return attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}
