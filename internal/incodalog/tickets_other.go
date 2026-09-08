//go:build !windows

package incodalog

// The live-ticket rail is WINDOWS-ONLY: incoda's ticket lock is a kernel
// byte-range (LockFileEx) protocol, and without it held cannot be
// distinguished from free. TicketLive alone keeps the per-ticket safe
// direction (everything reads live); the enumeration functions below are
// INERT off-Windows - they enumerate nothing, so the pure-ticket half of
// the ACTIVE rail does not exist here. This is a stated gap, not a silent
// safe default: reap is Windows-first, and these stubs exist so the
// package compiles elsewhere.
func TicketLive(path string) bool { return true }

// LiveTicketDirs: nothing enumerable off-Windows (the rail is Windows-only).
func LiveTicketDirs() []string { return nil }

// LiveTicketsUnder: no probe off-Windows (the rail is Windows-only).
func LiveTicketsUnder(root string) bool { return false }

// LiveTicketHit: no probe off-Windows (the rail is Windows-only).
func LiveTicketHit(root string) (hit, unknown bool) { return false, false }

// ProbeRail: no enumeration off-Windows (the rail is Windows-only).
func ProbeRail() RailHealth { return RailHealth{} }
