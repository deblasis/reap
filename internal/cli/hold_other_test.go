//go:build !windows

package cli

import (
	"os"
	"testing"
)

// holdNoDelete on non-Windows: a plain open holds the inode (unlink
// succeeds but the data lives); prune failures are exercised on Windows.
func holdNoDelete(t *testing.T, path string) (*os.File, error) {
	t.Helper()
	return os.Open(path)
}
