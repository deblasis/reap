// reap: know quickly what disk space is safely cleanable, and clean it easily.
//
// One-shot CLI in the incoda style: small internal packages, external tools
// (git, jj, gh) driven through exec with per-call budgets, verdicts that only
// ever degrade (never strengthen) when a tool is missing or failing. The two
// invariants from the design spec govern everything: no path may reach SAFE on
// stale, missing, or errored evidence, and no path may reach deletion for a dir
// carrying any BLOCKED-class fact, except the one named orphaned carve-out.
package main

import (
	"os"

	"github.com/deblasis/reap/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
