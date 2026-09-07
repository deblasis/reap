//go:build !windows

package quarantine

import (
	"os"
	"testing"
)

// holdNoShare on non-Windows: a mandatory lock is unavailable unprivileged;
// the AddAll-failure fixture is Windows-driven.
func holdNoShare(t *testing.T, path string) (*os.File, error) {
	t.Helper()
	return nil, os.ErrPermission
}
