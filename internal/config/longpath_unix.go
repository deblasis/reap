//go:build !windows

package config

// longPath is the identity off Windows (no 8.3 short names there).
func longPath(p string) string { return p }
