# Rule block for agent instructions

Copy everything below the line into the machine's `~/.claude/CLAUDE.md` (or a
repository's `AGENTS.md`) so agents route disk cleanup through reap honestly.

---

## Disk reaping (reap) rules

reap verdicts directories (SAFE / BLOCKED / MANUAL / ACTIVE / KEEP) from git
and jj state, open PRs, age and incoda activity, and deletes ONLY the SAFE
set, after a printed plan, with a write-ahead audit trail.

- You may freely run `reap scan`, `reap plan`, `reap holds`, `reap log`,
  `reap activity`, `reap quarantine list`, `reap doctor`, and propose
  deletions by showing plan output to the user.
- `reap apply` (with or without `--yes`), `reap discard`, `--no-quarantine`,
  `reap quarantine prune`, and hold changes are HUMAN decisions. Run them
  only when the user asked in the current session, always show the plan
  first, and never schedule or chain them on your own.
- `reap apply` without `--yes` in a non-TTY context is refused by the tool
  (exit 121). That refusal is working as designed; do not work around it.
  `--no-quarantine` is TTY-only over `--yes` (exit 120 without one), and
  `reap quarantine prune` carries the same confirmation choreography as
  apply.
- `--override-manual` relaxes only the MANUAL gate, only for the named path.
  If the tool refuses it, the refusal names why; surface that, do not retry
  variations.
- A BLOCKED row means real work exists (dirty files, unpushed commits, an
  open PR). Never delete around it; the resolution is push, merge, or
  `reap discard` with quarantine.
- Scratch dirs have no git safety net. 7-21 days idle verdicts MANUAL
  (judgment), 21+ days SAFE. If you parked files in a scratch dir that is
  now in a plan, say so before the user approves.
