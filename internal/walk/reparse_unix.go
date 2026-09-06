//go:build !windows

package walk

import "os"

// IsReparse reports whether path is a symlink (the Unix reparse analog).
func IsReparse(path string, d os.DirEntry) (bool, error) {
	if d != nil {
		return d.Type()&os.ModeSymlink != 0, nil
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode()&os.ModeSymlink != 0, nil
}
