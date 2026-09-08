//go:build windows

package incodalog

import (
	"github.com/deblasis/reap/internal/lockfile"
)

// lockfileOpenForTest opens a ticket file the way TicketLive does (the
// fixture's "another process" holder is just a second handle).
func lockfileOpenForTest(path string) (*lockfile.File, error) {
	return lockfile.Open(path)
}
