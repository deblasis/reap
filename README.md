# reap

Know quickly what disk space is safely cleanable, and clean it easily.

reap scans configured workspace roots, verdicts every directory (SAFE / BLOCKED /
MANUAL / ACTIVE / KEEP) from git and jj state, open PRs, age and incoda job-lane
activity, then deletes exactly the SAFE set after a printed plan, with a
write-ahead audit trail. Two invariants govern everything: no directory may
verdict SAFE on stale, missing, or errored evidence, and no path may reach
deletion for a directory carrying any BLOCKED-class fact, except the one named
orphaned carve-out behind a TTY-only hardened confirm.

Status: under construction (M1: scan + verdict engine). The command surface,
verdict matrix, and every safety contract live in the design spec.

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
```

Private tool for one workstation; sibling of [incoda](https://github.com/deblasis/incoda).
