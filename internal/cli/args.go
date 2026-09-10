package cli

import "strings"

// flagsFirst reorders args so every flag token (and its value) precedes the
// positionals: Go's flag package stops parsing at the first positional, and
// the tool's own usage lines print PATH-first spellings (`reap hold PATH
// [--for DUR]`, `reap discard PATH... [--yes]`) that silently changed
// meaning before this (the full-implementation board: the refusals were
// loud and safe, but the documented grammar must parse as printed).
func flagsFirst(args []string) []string {
	valueFlags := map[string]bool{
		"--for": true, "--older-than": true, "--to": true, "--since": true,
		"--min-gb": true, "--roots": true, "--include": true,
		"--exclude": true, "--override-manual": true,
	}
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && a != "-" && a != "--" {
			flags = append(flags, a)
			if valueFlags[a] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}
