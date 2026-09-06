//go:build windows

package auditlog

import (
	"golang.org/x/sys/windows"
)

func diskFree(path string) uint64 {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}
	var free, total, freeTotal uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &freeTotal); err != nil {
		return 0
	}
	return free
}
