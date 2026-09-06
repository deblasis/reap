// Package cli wires subcommand dispatch. It is the only place that knows the
// command names; the grammar block in the design spec is normative, and a flag
// existing in the spec but missing here (or vice versa) is a bug.
package cli

import (
	"fmt"
	"io"
)

// Exit codes, tool-wide per the spec: 0 success, 120 usage, 122 config/state/
// lock. The apply/discard/prune family adds 2, 121, 123, 124, 125 (see
// applycmd when it lands). Read-only commands never emit the family codes.
const (
	ExitOK    = 0
	ExitUsage = 120
	ExitState = 122
)

// Version is stamped at build time with -ldflags; the zero value means dev.
var Version string

// Main dispatches args and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	cmd, _ := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Fprintf(stdout, "reap %s\n", versionLabel())
		return ExitOK
	case "help", "-h", "--help":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "reap: unknown command %q\n\n", cmd)
		usage(stderr)
		return ExitUsage
	}
}

func versionLabel() string {
	if Version == "" {
		return "(dev)"
	}
	return Version
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: reap <command> [flags]

commands:
  version    print the build version
  help       this help

scan, plan, apply, discard, activity, log, quarantine, hold, unhold, holds,
doctor land with their milestones (see the design spec's normative grammar).
`)
}
