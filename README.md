# reap

Know quickly what disk space is safely cleanable, and clean it easily.

reap scans configured workspace roots and verdicts every directory - SAFE,
BLOCKED, MANUAL, ACTIVE or KEEP - from git and jj state, open pull requests,
age, and incoda job-lane activity. Then it deletes exactly the SAFE set
after a printed plan, with a write-ahead audit trail and quarantine bundles
for everything that had unsaved work. It is built for the machine where a
dozen agent sessions and worktrees eat a terabyte and nobody remembers which
half is regenerable.

## The safety model

Two invariants govern every line:

1. **No directory may verdict SAFE on stale, missing, or errored evidence.**
   A tool that failed silently is treated as a tool that failed: git/jj/gh
   being missing, a repo being unreadable, or the open-PR state being
   unknown all weaken the verdict, never leave it clean.
2. **No directory carrying any BLOCKED-class fact may be deleted** - not
   with `--yes`, not with `--include`, not with `--override-manual` - except
   one named carve-out (orphaned worktrees/workspaces) behind a TTY-only
   hardened confirm with a capped plain-copy snapshot first. Holds and protect globs
   beat every rule and every flag.

What reap reads but never touches: your work. Uncommitted files, stashes,
unpushed commits (branch or reflog-only), open PRs - all BLOCKED. Deleting
them is `reap discard`, which quarantines a git bundle first and can restore
it byte-for-byte afterwards.

## A demo

`demo/demo.sh` builds a sandbox world (an idle scratch dir you pinned, a
newer one, a pushed repo, a dirty repo), then walks the whole lifecycle.
Nothing outside the sandbox is touched:

```sh
sh demo/demo.sh            # or: sh demo/demo.sh ./path/to/reap
```

What it looks like (verbatim from a Windows run, long paths elided;
identical on macOS and Linux - on a machine without `gh`, the clean repo
honestly verdicts `gh-unavailable` instead of `clean + fully pushed`, and
nothing else changes):

```text
=== scan - what exists, and what each dir is

> reap scan
reap scan                                                          2026-09-10 18:10
roots: .../reap-demo-7C8Vih/world  4 dirs, 0.0 GB logical

BLOCKED 1 dirs    0.0 GB   waiting on you: push or discard
    0.0 GB  ...\world\dirty-repo 1 tracked-modified, 0 untracked
         last: no incoda record
         hint: commit+push the work, or reap discard ...\world\dirty-repo

MANUAL  1 dirs    0.0 GB   judgment calls (run reap plan --include <code> to widen)
    0.0 GB  ...\world\scratch-recent scratch idle 12 days (7-21)
         last: no incoda record
         hint: wait, or widen with --include scratch-recent

KEEP    1 dirs    0.0 GB   held or protected (holds expire in 29d)
    0.0 GB  ...\world\scratch-old held by user

SAFE    1 dirs    0.0 GB   ready to reap: reap plan, then reap apply
    0.0 GB  ...\world\clean-repo clean + fully pushed

sizes are logical; hardlinked content may reclaim less (zig lane cache shares bytes)
    0.0 GB  clean-pushed             1 dirs
    0.0 GB  dirty-files              1 dirs
    0.0 GB  held-by-user             1 dirs
    0.0 GB  scratch-recent           1 dirs

=== plan - exactly what a plain apply would delete (the SAFE set only)
# (the held scratch dir is KEEP, so only the clean-pushed repo plans)

> reap plan
reap will permanently delete 1 directories, logical 0.0 GB, expected reclaim ~0.0 GB (not recycled)
     0.0 GB  ...\world\clean-repo  [clean-pushed]
dry-run: nothing will be deleted

=== holds - releasing the pin lets the dir back into the plan

> reap holds
...\world\scratch-old  expires in 29d

> reap unhold ...\world\scratch-old
0 hold(s) recorded

> reap plan
reap will permanently delete 2 directories, logical 0.0 GB, expected reclaim ~0.0 GB (not recycled)
     0.0 GB  ...\world\clean-repo  [clean-pushed]
     0.0 GB  ...\world\scratch-old  [scratch-idle]
dry-run: nothing will be deleted

=== apply - delete the SAFE set, with the write-ahead audit trail

> reap apply --yes
reap will permanently delete 2 directories, 0.0 GB logical (not recycled)
preflight: 256 MB free required, 60855 MB free
deleted 2 dirs (logical 0.0 GB, expected reclaim ~0.0 GB), excluded 0 (0.0 GB below floor), skipped 0 (0.0 GB): none

=== discard - resolve a BLOCKED dir: quarantine it, then delete

> reap discard ...\world\dirty-repo --yes
discarded 1 dirs; freed ~0.0 GB now (dir 0.0 GB, bundle 0.0 GB kept); 0.0 GB more once the quarantine is pruned

=== quarantine list - what recovery exists, and how it is doing

> reap quarantine list
     0 MB    0d  20260910-181134-dirty-repo  delta base=b66be2354d source=...\world\dirty-repo state=verified-ok
  restore: reap quarantine restore 20260910-181134-dirty-repo

=== quarantine restore - prove the recovery is real (the dirty edits come back)

> reap quarantine restore 20260910-181134-dirty-repo --to ...\recovered
restored 20260910-181134-dirty-repo -> .../recovered (capture ref refs/reap/capture-20260910-181134 materialized; pinned refs under refs/reap/*)

recovered file says: uncommitted edits - the only copy

=== log - every decision reap made, write-ahead, one line per event

> reap log
2026-09-10T15:11:33  intent    begin     ...\world\clean-repo
2026-09-10T15:11:33  result    deleted   ...\world\clean-repo
2026-09-10T15:11:33  intent    begin     ...\world\scratch-old
2026-09-10T15:11:33  result    deleted   ...\world\scratch-old
2026-09-10T15:11:33  envelope  run end: deleted=2 skipped=0
2026-09-10T15:11:34  intent    begin     ...\world\dirty-repo
2026-09-10T15:11:36  result    deleted   ...\world\dirty-repo
2026-09-10T15:11:36  envelope  run end: deleted=1 skipped=0

```

## Install

Both scripts verify the SHA-256 before installing anything:

```sh
curl -fsSL https://raw.githubusercontent.com/deblasis/reap/main/install.sh | sh
```

```powershell
irm https://raw.githubusercontent.com/deblasis/reap/main/install.ps1 | iex
```

Or from source (Go 1.24+): from a checkout,
`go install ./cmd/reap`. Prebuilt binaries for Windows, macOS and Linux
(amd64 and arm64) ship with every release.

reap deletes directories for a living. Read the safety model above before
pointing it at anything you love, and start with `reap plan`, which prints
exactly what an apply would delete and deletes nothing.

## Quickstart

reap works from one config file, created on first run at
`%LOCALAPPDATA%\reap\config.json` (`~/Library/Application Support/reap`
on macOS, `~/.local/state/reap` on Linux; `$REAP_DIR` overrides):

```json
{
  "roots": ["C:/wt", "D:/code"],
  "protect": ["**/node_modules"],
  "thresholds": {"active-hours": 48, "scratch-safe-days": 21}
}
```

Then the loop is three commands:

- `reap scan` - the table above. Read-only, always.
- `reap plan` - the deletion set (SAFE by default; `--include <code>`
  widens into judgment-class MANUAL rows, never into unread state).
- `reap apply` - TTY confirm or `--yes`, then delete with a write-ahead
  audit trail, re-verifying every verdict at full strength seconds before
  each deletion.

Something has unpushed work? `reap discard <path>` quarantines a git bundle
covering every recoverable class (uncommitted files, stashes, unpushed
commits, reflog-only commits, jj changes) and then deletes;
`reap quarantine restore <id>` brings it back. Pin anything you want kept:
`reap hold <path>` beats every rule.

## Commands

```
reap scan      [--roots PATH]... [--min-gb N] [--no-gh] [--no-jj] [--json]
reap plan      [--roots PATH]... [--min-gb N] [--no-gh] [--no-jj]
               [--include CODE]... [--exclude CODE]... [--json]
reap apply     [--roots PATH]... [--min-gb N] [--no-gh] [--no-jj]
               [--include CODE]... [--exclude CODE]...
               [--override-manual PATH]... [--yes] [--dry-run] [--json]
reap discard   PATH... [--yes] [--no-quarantine] [--json]
reap activity  [--since DUR] [--json]
reap log       [--since DUR] [--json]
reap quarantine [list | prune [--older-than DUR] [--yes] [--json]
                | restore <id> [--to PATH] [--json]]
reap hold PATH [--for DUR]
reap unhold PATH
reap holds     [--json]
reap doctor
reap version
```

Exit codes mean things: `0` fully executed, `2` executed with skips, `120`
usage, `121` not interactive, `122` config/state/lock, `123` root missing,
`124` deletion failed (path named), `125` quarantine failure. Scripts can
trust them.

## The verdict matrix

Every directory gets exactly one verdict, from the full fact set:

| Verdict | Meaning | Examples |
|---|---|---|
| SAFE | regenerable or fully pushed | clean+pushed repos, scratch idle past the threshold |
| BLOCKED | your unsaved work | dirty files, stashes, unpushed commits, open PRs |
| MANUAL | a judgment call | recent scratch, nested repos, parent of live worktrees |
| ACTIVE | touched recently | anything with writes inside the active window, live incoda jobs |
| KEEP | pinned | holds, protect globs, reparse points |

A BLOCKED-class fact shadows everything below it: a directory that is both
held and dirty shows KEEP, but the dirty fact is recorded and any attempt to
widen into it is refused by name.

## incoda integration

If you use [incoda](https://github.com/deblasis/incoda) (the local job lane),
reap reads its ticket rail and lane.log: a directory with a live incoda job
verdicts ACTIVE no matter what the filesystem says, and scan rows carry
`last: <owner, when, reason>` attribution. incoda v0.4.0+ logs `dir=`/
`reason=`/`owner=` on every lifecycle line, which is what makes the
attribution exact; `reap doctor` reports the coverage share.

## Scope and non-goals

reap is a local, read-everything-then-delete tool. Not in scope: scheduling,
remote machines, background daemons, an HTML dashboard (`scan --json` is the
integration point), or deleting anything a human has not seen in a plan
first.

## Development

```sh
just ci        # gofmt no-op, go mod tidy no-op, go vet, the full suite
```

The suite (~140 tests, 15 packages) runs serialized (`go test -p 1`): it
builds real git/jj repositories, drives real PTYs for the TTY-only gates,
and proves quarantine recovery by restoring bundles into fresh repos. A
flake hides regressions in a tool that deletes; serialized runs stay honest.
AGENT-RULE.md is the pinned agent-facing contract for running heavy work
under the machine's job lane.

The full normative design - the verdict matrix order rules, the exit band,
the closed enums, the audit ledger shape - lives in
[docs/DESIGN.md](docs/DESIGN.md).

Status: v0.2.0. The implementation passed a multi-round adversarial review
at the bar "all three independent seats (engineering, reliability,
spec-conformance) rate it 9/10 or higher with no major findings"; the safety
contracts are pinned by tests that redden when their own mutation is
reverted.
