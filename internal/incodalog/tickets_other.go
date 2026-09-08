//go:build !windows

package incodalog

// TicketLive on non-Windows: incoda itself is Windows-first; without the
// kernel byte-range protocol the probe cannot distinguish held from free,
// so it reports LIVE (the safe direction: absent evidence must never read
// as inactive).
func TicketLive(path string) bool { return true }

// LiveTicketsUnder mirrors TicketLive's conservative default.
func LiveTicketsUnder(root string) bool { return false }
