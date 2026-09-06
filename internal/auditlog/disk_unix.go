//go:build !windows

package auditlog

import "golang.org/x/sys/unix"

func diskFree(path string) uint64 {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0
	}
	return uint64(st.Bavail) * uint64(st.Bsize)
}
