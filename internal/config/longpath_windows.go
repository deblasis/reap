//go:build windows

package config

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// longPath expands 8.3 short components (PROGRA~1, ALESSA~1) to long forms so
// paths from different sources (Go's temp dirs hand back short forms; git and
// jj metadata usually record long ones) compare equal. Called from Canonical,
// which every path comparison in reap funnels through.
func longPath(p string) string {
	if p == "" || len(p) < 4 {
		return p
	}
	p16, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	buf := make([]uint16, len(p)+260)
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetLongPathNameW")
	for {
		n, _, _ := proc.Call(
			uintptr(unsafe.Pointer(p16)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 {
			return p // not expandable or not found; the input is still usable
		}
		if int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n])
		}
		buf = make([]uint16, n)
	}
}
