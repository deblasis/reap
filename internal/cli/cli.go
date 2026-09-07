// Package cli wires subcommand dispatch. It is the only place that knows the
// command names; the grammar block in the design spec is normative, and a flag
// existing in the spec but missing here (or vice versa) is a bug.
package cli

import (
	"fmt"
	"io"
	"os"
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
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Fprintf(stdout, "reap %s\n", versionLabel())
		return ExitOK
	case "scan":
		return cmdScan(rest, stdout, stderr)
	case "plan":
		return cmdPlan(rest, stdout, stderr)
	case "apply":
		return cmdApply(rest, stdout, stderr, os.Stdin)
	case "discard":
		return cmdDiscard(rest, stdout, stderr, os.Stdin)
	case "log":
		return cmdLog(rest, stdout, stderr)
	case "quarantine":
		return cmdQuarantine(rest, stdout, stderr, os.Stdin)
	case "doctor":
		return cmdDoctor(rest, stdout, stderr)
	case "hold":
		return cmdHold(rest, stdout, stderr)
	case "unhold":
		return cmdUnhold(rest, stdout, stderr)
	case "holds":
		return cmdHolds(rest, stdout, stderr)
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
  scan       walk configured roots and verdict every directory
  plan       resolve the deletion set (SAFE default; --include widens)
  apply      re-verify and delete the plan (write-ahead audit; --yes or TTY)
  discard    quarantine-then-delete BLOCKED dirs (reap discard PATH...)
  log        read the deletion ledger (reap log [--since DUR])
  quarantine list / prune / restore snapshot sessions
  doctor     state-of-the-world readout (roots, lock, quarantine, ledger)
  hold       pin a path against deletion (reap hold PATH [--for DUR])
  unhold     release a pin
  holds      list pins with days remaining
  help       this help

reap scan  [--roots PATH]... [--min-gb N] [--no-gh] [--no-jj] [--json]
reap plan  [--roots PATH]... [--min-gb N] [--no-gh] [--no-jj]
           [--include CODE]... [--exclude CODE]... [--json]
reap apply [--roots PATH]... [--min-gb N] [--no-gh] [--no-jj]
           [--include CODE]... [--exclude CODE]... [--override-manual PATH]...
           [--yes] [--dry-run] [--json]
reap discard PATH... [--yes] [--no-quarantine] [--json]
reap quarantine [list [--json] | prune [--older-than DUR] [--yes] [--json]
                | restore <session> [--to PATH]]
reap log [--since DUR] [--json]
reap doctor

activity lands with its milestone (see the design spec's normative grammar).
`)
}

// multiFlag collects a repeated string flag (--roots a --roots b).
type multiFlag []string

func (m *multiFlag) String() string { return "" }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
