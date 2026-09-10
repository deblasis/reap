# reap: know quickly what disk space is safely cleanable, and clean it easily

Status: design v7 (2026-09-06), reviewed and shipped. The design passed a
six-round adversarial panel (final round 10,9,9,9,9,9), and the
implementation passed a 21-round three-seat review (engineering /
reliability / spec-conformance, all >= 9/10 with no majors) in 2026-09.
Repo: deblasis/reap. Single Go binary; runtime deps are only git / jj / gh found
on PATH, plus golang.org/x/sys for Windows file handles.

## Problem

The workstation (ryzen7pro, 1.86 TB) runs chronically near-full. Measured 2026-09-06: ~305 GB sits
in ~470 activity directories across the machine's workspace roots and
per-PR clones. Nothing reaps them, because "is this safe to delete" is expensive to
answer by hand: it needs git dirty/unpushed state, open-PR state, jj state for jj workspaces, age,
and whether any session is still using the dir.

The same measurement gave the honest verdict split of a real cleanup pass: SAFE 145 dirs / 7.9 GB,
BLOCKED 84 / 51.2 GB (dirty or unpushed), MANUAL 93 / 55.7 GB, ACTIVE 65 / 23.8 GB. Two truths
follow. First, the main screen is the BLOCKED-with-reasons list, which the user resolves by pushing
or discarding; only then does the GB flow out. Second, recurring throughput is modest: roughly the
weekly accrual of finished activity dirs, not a buried treasure. reap earns its keep by making the
resolution queue visible and by deleting the residue safely; the two largest consumers (a 499 GB
Hyper-V vhdx and a zig lane cache that grew 116 GB in 4 days) are out of scope by design and have
their own runbooks.

reap answers two questions per directory: how much space, and what verdict (SAFE / BLOCKED /
MANUAL / ACTIVE / KEEP) with a machine-stable reason code and a human line. Then it deletes
exactly the SAFE set, after printing the plan, with a write-ahead audit trail. Two invariants
govern everything below: no path may reach SAFE on stale, missing, or errored evidence, and no
path may reach deletion (widen, override, or apply) for a dir carrying any BLOCKED-class
fact, except the one named orphaned carve-out with its interactive-only hardened confirm.

## Goals

1. `reap scan` in under ~3 minutes warm over all configured roots, verdicts conservative enough to
   act on (both invariants above, fault-injection tested).
2. `reap apply` deletes only verdict-SAFE paths (plus explicitly overridden judgment-class MANUAL
   ones), re-verified at deletion time with cache-bypassed facts, fully audited write-ahead.
3. incoda lane.log attribution as best-effort enrichment when present (the incoda PR below is
   outside reap's control); doctor reports the share of dirs that have real dir= attribution so
   thinness is visible, not assumed.
4. jj workspaces handled natively (verdict + deregister-then-delete on apply), same as git ones.
5. Zero-daemon: every command is one-shot. State is files on disk, locked during writes.
6. reap's own footprint is bounded and visible: quarantine retention, audit-log rotation, doctor
   and scan-footer readouts. A disk-reclaim tool must not manufacture its own unreaped mass.
  doctor's residue sweep is deadline-bounded and reports an explicit INCOMPLETE line naming
  the remainder when the deadline trips.

## Non-goals (v1)

- No HTML dashboard, no TUI, no web server. `scan --json` is the integration point.
- No process-level disk tracing (ETW/USN). Rejected in brainstorm: must run before allocation,
  needs admin, cannot touch the existing backlog, and "done?" is a git-state question.
- No build-artifact purging inside kept repos (measured: ~6 GB total, regenerable). Future work.
- No recycle-bin mode. Deletions are permanent (recycling to the same disk reclaims nothing);
  the audit trail, quarantine bundles for `discard`, and holds are the safety story.
- No cross-machine anything, no background scheduling. Future: history.jsonl via Task Scheduler.
- Declined with reason: `apply --from-plan FILE` artifact (shared filter flags instead; a saved
  plan can go stale, the flags cannot); per-repo `gh pr list` (one author-scoped search instead,
  which also fixes the fork-PR blind spot; per-CANDIDATE-repo listing stays declined - the fan-out is per PR base, bounded); shipping scan-only and gating the delete machinery on
  demonstrated SAFE volume (the measured 7.9 GB SAFE + 37 GB user-approved MANUAL already
  justified apply in the real pass; milestones below still deliver scan first); full recursive
  fact-gathering into nested repositories (detection routes MANUAL instead; see matrix); bundled
  capture of nested repositories inside a discard (v1 refuses and names them; nested bundles are
  future).

## Approach

One-shot CLI in the incoda style: small internal packages, exec external tools (git, jj, gh) with
per-call timeouts and no Go-module dependencies on them, degrade to weaker verdicts (never
stronger) when a tool is missing, failing, timing out, or producing unparseable output. Windows
first, portable by incoda's patterns.

Milestones (each independently useful, attribution never on the critical path):
- M1: scan + verdict engine + fixtures. Delivers "know quickly" standalone. Emits no discard hints.
- M2: apply + write-ahead audit + locking + AGENT-RULE block (the destructive command and its
  governing rule text ship together).
- M3: discard + quarantine machinery (snapshot, list/prune) + hold/expiry + log + doctor. The
  BLOCKED-resolution half of the core promise; BLOCKED rows begin advertising `reap discard` only
  now.
- M4: activity/attribution (lane.log parser, live tickets) + the incoda dir= PR (external).

## Command surface (normative grammar)

```
reap scan       [--roots PATH]... [--min-gb N] [--no-gh] [--no-jj] [--json]
reap plan       [--roots PATH]... [--min-gb N] [--no-gh] [--no-jj]
                [--include CODE]... [--exclude CODE]... [--json]
reap apply      [--roots PATH]... [--min-gb N] [--no-gh] [--no-jj]
                [--include CODE]... [--exclude CODE]...
                [--override-manual PATH]... [--yes] [--dry-run] [--json]
reap discard    PATH... [--yes] [--no-quarantine] [--json]
reap activity   [--since DUR] [--json]        (incoda lane.log digest; NOT reap's own history)
reap log        [--since DUR] [--json]        (reads reap.log and all rotations, oldest first)
reap quarantine [list | prune [--older-than DUR] [--yes] [--json]
                | restore <id> [--to PATH] [--json]]
reap hold PATH [--for DUR]     reap unhold PATH     reap holds [--json]
reap doctor
```

The synopsis is the normative grammar: a flag specified in prose but missing here (or vice versa)
is a spec bug to catch in review. Bare `reap quarantine` is `list`.

Exit band, tool-wide: every command uses 0 success, 120 usage, 122 config/state/lock error; the
apply/discard/prune family adds 2 executed-with-skips, 121 not interactive, 123 root missing,
124 deletion failed (path named), 125 quarantine/prune failure (source untouched where that is
the contract). Read-only commands never emit the family-specific codes.

`reap apply --dry-run` is byte-identical to `reap plan` with the same flags. `--roots` is a
narrowing filter on scan, plan and apply alike (same safe direction as --exclude: less is listed,
less is planned, less is deleted; never more). `--min-gb N` is a listing and planning floor only,
never a verdict input: below-floor SAFE dirs are reported as an excluded bucket in the summary and
in apply --json, never as skips. Verdict strength is always full: `--no-gh`/`--no-jj` weaken
verdicts (to MANUAL, never toward SAFE) identically wherever they are passed.

- `scan` walks configured roots, classifies, enriches, verdicts, prints the grouped table and
  totals (with a per-reasonCode count + GB breakdown so bucket inflation is visible, and a
  quarantine footer when bundles exist). Exit 0 always.
- `plan` resolves the deletion set: verdict-SAFE by default; `--include reasonCode` widens only
  into judgment-class MANUAL verdicts with no BLOCKED-class fact present (see Deletion
  reachability); a code that resolves to BLOCKED/ACTIVE/KEEP paths, or to a dir carrying any
  BLOCKED-class fact, is a usage error naming the path; `--exclude` narrows.
- `apply` prints the plan ("will permanently delete N directories, X GB logical (not recycled); M
  widened via <code>"), preflights free space against a small configured floor (min-free-mb,
  default 256 MB: enough for audit growth and rotation; apply frees space, the floor exists so
  the audit append can never wedge), then requires confirmation: interactive TTY reads
  `Proceed? [y/N]` defaulting to N (Enter/EOF declines); no TTY and no `--yes` refuses with
  "reap apply deletes permanently; pass --yes to confirm when not interactive" and exit 121.
  Never infers confirmation from EOF. It takes the exclusive state lock, then per path:
  re-verifies the verdict seconds before deletion with a forced fresh walk (never any cache;
  walk), skips and logs anything that changed, deletes children before parents for detected
  lineage, deletes directory contents before `.git`/`.jj` so partial failure preserves history
  and reflog, deregisters before removal (`git worktree remove --force` fallback rm +
  `git worktree prune`; jj: `jj workspace forget` must succeed before rm, failure routes MANUAL),
  appends write-ahead audit lines, and ends with "deleted N dirs (X GB), excluded M (Y GB below
  floor), skipped K (Z GB): <reasons>". `--override-manual PATH` relaxes only the MANUAL gate for
  exactly that path, and only for judgment-class codes with no BLOCKED-class fact (see Deletion
  reachability); SAFE/BLOCKED/KEEP are never overridable; holds and protected globs beat every
  flag including this one (tested). `--json` emits {runId, planned[], widened[], deleted[],
  skipped[{path, why}], excluded[]}.
- `discard PATH...` resolves BLOCKED dirs inside the tool, one plan and one confirmation covering
  all paths, each gated individually. Input contract: eligibility is keyed on the FULL fact set
  (Deletion reachability), not the displayed row: a dir carrying any BLOCKED-class fact is
  discard-eligible regardless of displayed verdict (this un-strands shadowed parents); dirs with
  none are not. SAFE paths are pointed at plan/apply; KEEP paths (holds, protected globs,
  reparse points) refuse unconditionally; the parent-of-live-children and nested-repositories
  checks run at discard re-verify exactly as at apply, and a dir containing nested repositories
  refuses, naming them. Orphaned-worktree and orphaned-workspace dirs refuse with a pointed
  message: capture needs a readable git backend and the parent is gone; their only deletion
  path is the carve-out (`reap apply --override-manual`, which asks the TTY-only hardened
  confirm). Dirs with no BLOCKED-class fact whose displayed verdict is MANUAL or ACTIVE refuse
  with a pointer to their own path (judgment dirs: "run reap plan --include <code>
  or --override-manual"). Exit band, two waves: refusals that fire BEFORE the ledger opens
  (the wave-0 rails: missing, reparse, held, protected, pure-jj) exit 120 with nothing
  recorded; refusals that fire after the ledger opens (class/eligibility, the confirm window)
  land in the 2 executed-with-skips band with a skip record, so the band and the ledger
  agree on what ran.
  Per path: walk-tripwire + rename probe first (same as apply), free-space preflight against
  max(quarantine cap, measured capture bytes) with the 2.5x margin ("quarantine needs A GB, B
  free" refusal; when the cap binds the message names quarantine-cap-gb), snapshot completely
  (below), verify (bundle verify + fsync of the quarantine dir) BEFORE any deletion, then delete
  via the same lineage-ordered deregister-before-rm path as apply. Prompt copy: "quarantining to
  %LOCALAPPDATA%\reap\quarantine\<ts>-<name> (cap N GB on the delta), then permanently deleting
  X GB". No TTY and no `--yes` refuses like apply (exit 121). Over-cap or verify failure refuses
  with the dir untouched (exit 125). `--no-quarantine` requires a live interactive TTY
  confirmation naming exactly what will NOT be captured; it ignores --yes entirely, and
  non-TTY plus --no-quarantine is a usage error (120) — the mechanical backstop, same principle
  as exit 121; the run still writes the manifest and logs mode=no-quarantine; agents are barred
  by rule. jj handling: colocated repos pin push-state commits under refs/reap/jj-N and export
  (below); pure jj dirs (no colocated git backend) refuse with a message naming the manual
  alternative, and their resolve hint says so. discard holds apply.lock for its entire run with
  the same write-ahead choreography as apply (intent line, result line, session envelope,
  runId), the same exit band, and the same deletion-set hardlink dedupe pass. It prints the
  two-number truth derived from that pass: "freed ~D GB now (dir X GB, bundle Y GB kept); Y GB
  more once the quarantine is pruned".
- `activity` digests incoda lane.log across queues into activity records. `log` lists past
  deletions from reap.log and all its rotations, oldest to newest (a rotation-boundary test
  asserts a run split across rotation is still fully listed; doctor reports the covered time
  span). `quarantine list` shows bundles with size, age, self-contained vs delta-dependent
  marking (with base SHA), at-risk marks from base revalidation, the past-retention annotation
  with the exact prune command, and each bundle's restore command; `prune [--older-than DUR]`
  defaults DUR to quarantine-retention-days (the config drives the default, not the other way
  round) and deletes expired bundles behind the full destructive choreography: plan line "will
  delete N bundles (X GB, oldest Yd): recovery for these discards ends here" (louder when any
  selected bundle is at-risk), `Proceed? [y/N]` or --yes, exit 121 when non-interactive, 124/125
  on failure with the bundle named; --json changes only the output format, never the
  confirmation choreography. `restore <id> --to PATH` recovers a bundle (see Quarantine
  snapshot).
- `hold`/`unhold`/`holds` manage pins: a held path (component-boundary prefix match) always
  verdicts KEEP. `--for` defaults to 30d; `holds` shows days remaining and flags holds on paths
  that no longer exist. Hold expiry surfaces at the moment of consequence: scan marks dirs whose
  hold expired within 7 days, and plan lists expired-hold paths in a distinct section with the
  expiry date. If apply.lock is held by a running apply, hold/unhold fails fast naming the holder
  PID and runId (exit 122); it never blocks (a hold that lands after the deletion would be worse
  than an honest refusal).
- `doctor` prints roots as expanded (wrong-context elevation visible), config and state paths,
  quarantine total bytes, oldest bundle age, and per-bundle revalidation states
  (verified-ok / at-risk / unverified), reap.log size and rotation state and covered time
  span, incoda state dir found and the share of candidate dirs with real dir= attribution, live
  `gh auth status` (found-but-unauthenticated reported, since it silently collapses SAFE), counts
  of dirs downgraded by gh/jj unavailability, free-space deltas since the last apply (from audit
  envelopes), candidate dirs carrying an aged .git/index.lock (the git-busy skip's remedy:
  delete it if no git is running), dirs carrying stranded refs/reap/* refs or
  .reap-probing/.reap-orphaned strays
  (with the exact restore command, and an unstage of the all-staged pair when present), and
  heals the strays (under apply.lock, or skipped while it is held; healing never overwrites: if
  both names exist, the stray is parked as `<name>.reap-orphaned-<ts>` and surfaced).

## Quarantine snapshot (completeness contract)

A quarantine bundle must capture everything the BLOCKED verdict was holding, or discard destroys
what it claims to rescue; it must do so at delta prices, or it refuses its own use cases; and it
must be FETCHABLE later, not merely packed. The governing principle, applied uniformly: bundles
materialize refs, never reflogs — so every recoverable tip gets a pinned named ref first.

Capture is NON-MUTATING by construction (the working tree is never swept; the index is saved and
restored; "refusal leaves the dir untouched" is literally true, and the crash fixture asserts
`git status` equals the pre-capture status, not just tree bytes):

1. `git add -A -f .` stages tracked-modified, untracked, AND ignored files into the index
   (working tree files stay on disk).
2. Plumbing commit: `git write-tree` then `git commit-tree` (parent = HEAD, or no parent on an
   unborn HEAD, which this path handles naturally) then `update-ref refs/reap/capture-<ts>` then
   restore the saved index on every path including abort. Only refs and objects are created.
3. Tip pinning (the generalization of stash pinning; nothing recoverable is left unnamed):
   - every branch tip counted by the unpushed fact: `refs/reap/unpushed-<branch>`
   - every reflog-only tip: `refs/reap/reflog-N`
   - every tag tip the unpushed count includes that is not reachable from another pinned ref:
     `refs/reap/tag-<name>` (closing the one class --all counts but pinning missed)
   - every stash generation from `git stash list`: `refs/reap/stash-N`
   - the capture commit: `refs/reap/capture-<ts>` (above)
   The bundle itself is literal syntax: the refs/reap/* set is enumerated via `for-each-ref`
   into an explicit `<base>..<ref>` list for `git bundle create` (a glob is not a valid range
   endpoint). Capture is git-exclusive: if `.git/index.lock` (or the worktree equivalent)
   exists at capture start, the path skips with reason git-busy; after restoring the saved
   index, its mtime is verified unchanged across the window and any detected interleaving is
   surfaced in the result line instead of silently restored over.
4. jj colocated: before `jj git export`, create temporary bookmarks at every commit matched by
   the same push-state revset the jj-unpushed fact uses, placed under the SAME namespace
   (`refs/reap/jj-N` via the git backend), so one namespace rule covers everything; the revset
   and count go in the manifest.
5. Incremental bundle: `git bundle create <dst> <base>..<ref>...` with the ref list enumerated
   per step 3's for-each-ref rule (plus refs/stash) — never a glob endpoint. Base selection
   pinned: the current branch's upstream-tracking ref if it exists, else the remote's default
   branch (origin/HEAD), else a per-branch range union; recorded in the manifest. The cap prices
   the DELTA; a small dirty worktree of a large parent (shared history) stays small, and delta
   bundles stay incremental at any size under the cap. The self-contained full `--all` fallback
   is a CAPTURE-TIME decision only: no usable base ref exists, or capture-time revalidation
   confirms the base is gone (priced under the same cap; if that exceeds the cap, refuse). After
   capture, at-risk is handled by marking and prune warnings, never conversion — the source dir
   no longer exists to re-capture from.
6. Completeness manifest in the quarantine dir: per-class coverage (capture ref, unpushed
   branch tips + counts, reflog tips + counts + days-to-expiry, stash generations, jj change
   count, dirty/untracked/ignored bytes, empty-directory names — git trees cannot represent
   empty dirs, so the manifest records them and restore recreates them), the base SHA and
   remote URL, self-contained vs delta-dependent, and the source path + runId for reverse
   lookup from reap.log.

Durability: manifest and bundle record the base; `quarantine list` and doctor revalidate delta
bundles against the recorded remote (one ls-remote each) with three explicit states —
verified-ok, at-risk (base SHA confirmed gone: force-push, squash-merge, deletion, routine
within a 30d retention window), unverified (ls-remote unreachable: offline/auth; shown as such
in list --json and doctor, never conflated with at-risk). Prune copy follows the states
exactly: at-risk gets the loud warning "deleting ends the last recoverable copy"; unverified
gets "could not verify the base (offline?); if the base is gone, deleting ends recovery";
verified-ok gets no warning. Delta bundles stay incremental at any size under the cap; the
self-contained full `--all` fallback is a capture-time decision only (no usable base exists,
or capture-time revalidation confirms the base is gone; priced under the same cap, else
refuse) — post-capture at-risk is marking and warnings, never conversion.
Preflight requires free space >= max(cap, measured dirty+untracked+ignored bytes) * 2.5 (the
capture transiently writes roughly the delta twice: staged blobs, then the bundle). On abort,
loose-object residue under .git/objects is reclaimable; doctor's stranded-ref entry reports the
reclaimable bytes with the scoped `git gc` command. `git bundle verify` + fsync of the quarantine
dir must pass before any deletion; refusal = dir untouched (exit 125); a failed verify is a hard
error naming the refs/reap/* ref where content provably lives.

`reap quarantine restore <id> [--to PATH]` is the first-class recovery command (the fixture
procedure, productized), mode-dispatched from the manifest: bundle bundles clone or fetch the
base per the manifest and materialize the capture and pinned tips; plain-copy bundles copy the
files back. Omitted --to defaults to the manifest's source path. It refuses a --to PATH that
exists and is non-empty (exit 120, naming what is there; recovery never deletes or overwrites
anything at the destination), recreates empty dirs, and on missing prerequisites names the
exact SHAs needed instead of a raw git error.

Fixture tests: discard a dirty+untracked+ignored repo, restore, diff against the original tree;
crash-after-capture asserts `git status` equals the pre-capture status and the tree is
byte-identical; a small dirty worktree of a large parent succeeds under the cap; restore from a
FRESH CLONE for: unpushed commits on another branch, reflog-only commits post-reset, a colocated
repo with 3 unpushed jj changes (asserting the commits are fetchable, not merely packed); a
locked ignored file aborts cleanly; unborn HEAD quarantines fine; over-cap and verify-failure
refusals leave the dir untouched; a large-content variant of the crash fixture covers the
intermediate-write footprint; log-line-to-bundle-to-restored-files walk.

## Verdict engine

Facts per dir, all via exec with budgets (git 30s, jj 30s, gh 15s per call; `git fetch` gets its
own 120s budget):

- git facts: `git status --porcelain --ignored` split into dirty (tracked-modified), untracked,
  and ignored counts and bytes; `git stash list` count; unpushed computed by decomposing
  `git rev-list --all --reflog HEAD --not --remotes` into branch-reachable (on some branch or
  HEAD) and reflog-only counts — branch-reachable covers branches, tags, stash tip, detached
  HEAD; reflog-only covers discarded-reset and pre-rebase generations, which self-heal via
  default 90-day reflog expiry and are reported with days-to-expiry so the rebase/squash-merge
  house workflow does not mint phantom forever-BLOCKED rows; upstream branch; remote freshness
  from FETCH_HEAD/last-fetch marker age; registered children (`git worktree list`, plus
  `.git/worktrees/*` even when the parent's git is broken); nested repositories = any
  `.git`/`.jj` below the candidate root.
- jj facts (colocated repos collect git facts too): working-copy push state = the working-copy
  commit and ancestors reachable from any remote bookmark; remote-bookmark recency from the last
  `jj git fetch` marker; `jj op log` recency; workspace parent resolution and `jj workspace list`
  children.
- gh facts: one gh fan-out per run, TWO-PHASE (gh 2.83 exposes no head-ref fields on search,
  verified): `gh search prs --author @me --state open --json repository --limit 200` for candidate
  base repos, then one `gh pr list -R <base> --json headRefName,headRepository` per hit repo
  (capped bases, pooled, wall-budgeted; truncated or over-cap results
  are gh-unavailable, not "no open PRs"; field names pinned by an assertion test). Join:
  headRepository == the slug of ANY configured remote of the dir (origin, upstream, a secondary
  fork: PR head repos vary by clone layout) AND headRefName == the dir's current or
  upstream-tracking branch. Any gh failure (missing, auth-expired, timeout, unparseable,
  truncated) = fact unavailable for every dir: verdicts needing it go MANUAL `gh-unavailable`,
  never "no open PRs". The unavailability NOTE (naming why: timeout, over-cap, auth) prints on
  stderr, including under --json, so stdout stays the pure machine channel.
- activity facts: lastActivity = max file mtime observed during the size walk, future mtimes
  clamped to now (clamped-file count surfaces on the entry). lastActivity NEVER comes from the
  size cache: SAFE-relevant facts always come from the current walk,
  and apply/discard re-verify always performs a fresh uncached walk of each planned dir.
- incoda attribution: join over max(enqueue, acquire, release) per dir; enqueue/acquire without
  a matching release counts as ACTIVE only if a live ticket backs it OR the event is within
  active-hours; reaped/giveup/kill/force-release are release-equivalent terminators. The
  live-ticket probe uses incoda's lock semantics (byte-range lock at offset 2^62; a naive
  offset-0 probe would read live tickets as free); a ticket that cannot be opened or probed for a reason other than having vanished is
  treated as live (a VANISHED ticket is a released one - the sweep's read layer
  distinguishes it). Any enumeration failure at any level of the ticket sweep (the queues dir
  existing but unlistable, one queue dir that will not enumerate, a ticket PERSISTENTLY held
  whose body cannot be read or parsed into a dir) reads live-or-unknown for every candidate:
  absent evidence must never read as inactive, and doctor names the failures. Transitions are
  not failures: incoda deletes tickets at release (a vanished ticket is a released one) and
  takes the lock before writing / rewrites the body at acquire, so a body-read failure
  re-probes liveness and re-reads once before it counts as unknown; a refusal caused by the
  unknown rail says 'enumeration incomplete' (see reap doctor), never 'a job landed'. The
  live set is re-probed under apply.lock at the confirm window (apply aborts the whole run
  at 122 naming the dir; discard drops the affected path, records a verdict-changed skip,
  and continues) and re-swept per path immediately before each deletion (an
  enqueued-not-yet-writing job mid-run holds no handles the tripwire or rename probe can
  see). An aborted run still writes its ledger envelope (an explicit event:'abort' line).
  Attribution is enrichment: absent lane.log data weakens nothing the walk and git/jj facts
  already establish. Overlapping configured roots are first-class: the deletion order is
  children-first across BOTH lineage and path nesting, a hold at/under a candidate refuses
  the candidate (holds beat every rule, in the containment direction too), and a scan row
  still standing at/under a candidate skips it as parent-of-live-children.

The cardinal rule: a dir may verdict SAFE only when every fact required by its row was obtained
fresh and parsed. Missing tool, nonzero exit, timeout, unparseable output, stale remote state, or
unwalkable size = the fact is unavailable and the dir lands MANUAL (`facts-unavailable`,
`state-unreadable`, `remote-stale`, `gh-unavailable`). There is no path to SAFE through missing
evidence.

Matrix, priority order (first match wins for DISPLAY; reachability is governed separately below).
reasonCode is a closed enum; the normative list lives in the Data model section and
--include/--exclude validate against it. Rows carry the strongest additional signal in their
detail (e.g. "nested-repositories (also: 12 unpushed commits)").

| Condition | Verdict | reasonCode |
|---|---|---|
| under a hold, or matches protected glob, or is itself a reparse point | KEEP | held-by-user / protected |
| live incoda ticket at/under dir, or live-backed/recent open incoda event | ACTIVE | incoda-live |
| lastActivity < active-hours (48h) | ACTIVE | active |
| kind = git-worktree-orphaned (parent gone or branch broken; detected by reading the .git file, no exec) | MANUAL | orphaned-worktree |
| kind = jj-workspace-orphaned (parent unresolvable; same no-exec detection) | MANUAL | orphaned-workspace |
| git repo, but status/rev-list could not run (locked index, corrupt .git) | MANUAL | state-unreadable |
| any other required git/jj/gh fact errored, timed out, or unparseable | MANUAL | facts-unavailable |
| kind = unknown (classifier could not determine what the dir is) | MANUAL | unknown-kind |
| nested .git/.jj present below the root | MANUAL | nested-repositories |
| repo with live registered children (worktrees, jj workspaces) | MANUAL | parent-of-live-children |
| dirty > 0 | BLOCKED | dirty-files (detail: a tracked, b untracked) |
| stash list non-empty | BLOCKED | stashes |
| ignored entries present | MANUAL | ignored-content (detail: n files, X GB) |
| branch-reachable unpushed > 0 | BLOCKED | unpushed-commits |
| reflog-only unpushed > 0 (no branch reaches them) | BLOCKED | unpushed-reflog (detail: n commits, expire in Nd; pushing clears nothing) |
| no remote configured | BLOCKED | no-remote |
| remote-tracking state older than remote-stale-hours (72h) | MANUAL | remote-stale (fetch needed) |
| branch in the open-PR set (any-remote join above) | BLOCKED | open-pr |
| jj: working copy or ancestors not on any remote bookmark | BLOCKED | jj-unpushed |
| jj: remote bookmarks stale (fetch marker older than window) | MANUAL | jj-remote-stale |
| jj: op log activity < active-hours | ACTIVE | jj-active |
| git clean + pushed (both counts zero) + stash-empty + ignored-empty + no live children + no nested repos; if colocated, jj facts also clean+pushed | SAFE | clean-pushed |
| scratch, lastActivity >= scratch-safe-days (21) | SAFE | scratch-idle |
| scratch, lastActivity >= scratch-manual-days (7) | MANUAL | scratch-recent |
| scratch, younger than scratch-manual-days | ACTIVE | scratch-fresh |

Orphaned rows rank above state-unreadable because orphan detection reads the .git file directly
(a missing parent is structural, not unreadable state); the classifier defines no-VCS-markers =
scratch, so unknown-kind is structurally rare and semantically "could not classify", which is
ignorance, not judgment (see Deletion reachability). The unpushed split exists so the house
workflow (rebase, force-push-with-lease, squash-merge, prune) does not mint phantom BLOCKED rows
whose "push" hint can never clear: reflog-only generations expire in N days, the hint says so,
and both counts ship as separate JSON fields.

Scan-time parent-of-live-children is deterministic: any live registered child routes the parent
MANUAL; apply's in-set check (children deleted first in the same run) is what unlocks a both-clean
  family, and it also tolerates a SELF-INFLICTED jj-active re-verdict on a jj parent (reap's own
  'jj workspace forget' writes an op into the parent's shared op store, so the parent can never
  re-verdict SAFE in-run): accepted only when the run can prove the parent's op-head set is
  exactly the one its own deregistration left (file-based names, fail-closed when unreadable);
  every other ACTIVE cause still skips
family, and the parent's hint says so. Every (kind, age) fixture must yield exactly one verdict
(matrix-completeness test). `state-unreadable` (repo-level) ranks above `facts-unavailable`
(tool-level); a locked-index fixture pins the order.

## Deletion reachability (the second invariant)

Widening (`--include`) and override (`--override-manual`) gate on the FULL fact set, never on the
displayed row, because specific rows can shadow BLOCKED-class facts (a nested clone is untracked
content: dirty AND nested; a dirty parent with a live worktree is both). discard eligibility is
keyed the same way: a dir carrying any BLOCKED-class fact is discard-eligible regardless of which
row displayed, and a dir without one is not, regardless of the displayed verdict:

- BLOCKED-class facts: dirty, stashes, unpushed (branch-reachable or reflog-only), no-remote,
  open-pr, jj-unpushed. If ANY is present, the dir is neither widen-eligible nor
  override-eligible, no matter which row displayed. Violation is a usage error naming the path
  and the shadowed fact.
- Ignorance-class codes: facts-unavailable, state-unreadable, remote-stale, jj-remote-stale,
  gh-unavailable, unknown-kind. Never override-eligible: overriding unread (or unclassifiable)
  state is a side door around the cardinal rule, and unknown-kind passes the fact gate only
  vacuously (nothing could be read). Refusal copy names the path, the unavailable fact, the
  reason ("overriding unread state is a side door around the cardinal rule"), and the remedy
  (fix the tool or rerun scan). Apply/discard re-verify requires these facts freshly
  obtainable, else the path skips with the reason.
- Judgment-class codes: ignored-content, orphaned-worktree, orphaned-workspace,
  nested-repositories, parent-of-live-children, scratch-recent. Override-eligible once the
  full-fact gate passes.
- The orphaned carve-out: an orphaned worktree or workspace can NEVER push its unpushed commits
  (parent gone) and can NEVER become readable (the gitdir is the state). A blanket full-fact
  refusal would strand the flagship class forever, so for orphaned kinds only, the BLOCKED-class
  facts do not block --override-manual; instead the override triggers a HARDENED CONFIRM whose
  modality is pinned to the tool's own backstop pattern: interactive TTY only, --yes does NOT
  satisfy it, non-TTY (agents) exits 121 with the counts in the refusal, and --include can never
  reach carve-out dirs. The prompt names the only-copy risk and the counts, distinguishing
  "N unpushed / M dirty" (parent present but broken) from "counts unknowable, parent gone"
  (a renamed parent misclassifies as orphaned; the prompt surfaces the stale gitdir path so the
  rename is discoverable), and the reap.log intent line records that the hardened confirm was
  shown with those counts. The confirm offers a capped plain-copy snapshot: a byte-for-byte
  file copy into the quarantine dir, labeled honestly in the manifest and result line as
  "files only, no git objects" (a worktree's objects live in the gone parent; the copy rescues
  working files, not commits). Its contract is explicit about both fit and failure: when the
  copy would exceed the cap the prompt says so ("plain-copy snapshot exceeds the cap (needs A
  GB, cap N GB): deletion is unrecoverable except for the file manifest — Proceed? [y/N]") and
  the run records mode=plain-copy-skipped-overcap, never a silent absence; when the offer is
  accepted, apply's free-space preflight floor rises to quarantine-cap-gb x quarantine-margin
  for that run and any write failure aborts the path with the dir untouched, partials cleaned,
  exit 125 — a confirmed snapshot is never replaced by a silent no-snapshot deletion. The
  capped top-level manifest is written for every carve-out deletion regardless. The plan
  renders carve-out paths as a distinct OVERRIDDEN-ORPHANED section. Every other kind keeps
  the strict gate; fault injection asserts a non-TTY
  `apply --yes --override-manual <orphaned>` is refused.

Hints are a function of the full fact set, never of the displayed code: a shadowed judgment row
rewrites its hint to name the blocking fact and the next mechanical step ("salvage files and
push the 2 commits, then --override-manual"; dirty-with-nested: "resolve the nested repo first"),
and --override-manual or --include is only ever advertised on actually-eligible dirs. A fixture
asserts hint-vs-eligibility consistency for every shadowed combination.

The fault-injection suite extends from "no path to SAFE" to "no path to deletion": no combination
of --include, --override-manual, discard, or apply can reach a dir carrying a BLOCKED-class fact
or an unread ignorance-class fact, except via the orphaned carve-out's hardened confirm. Residue
overlap (submodules present, fresh reflog) is noted in the plan row and the reap.log intent line
at the moment of deletion.

## Presentation (the main screen)

```
reap scan                                                                 2026-09-06 19:02
roots: <the machine's workspace roots>                       462 dirs, 291.4 GB logical

ACTIVE  61 dirs  23.8 GB   (touched <48h or fresh scratch; nothing to decide)
  6.5 GB  C:\temp\wintty-seam930      active (<48h)
           last: sess-42, 2h, "seam930 verify"

BLOCKED 84 dirs  51.2 GB   waiting on you: push or discard
 12.9 GB  C:\temp\muxc                 5 tracked-modified, 2 untracked
           last: sess-7, 3d, "muxc type check"
          hint: commit+push origin main, or reap discard C:\temp\muxc
  8.8 GB  C:\wt\train                  321 unpushed commits [shared lineage: 3 dirs, resolve at branch level]
 ...
MANUAL  89 dirs  54.1 GB   judgment calls (run reap plan --include <code> to widen)
  9.3 GB  C:\zc\envl                    scratch idle 12 days (7-21)
           last: no incoda record
          hint: nothing protects this; review, then --override-manual
  1.9 GB  C:\wt\pin084                  orphaned-worktree, files may be only copy (also: 2 unpushed)
          hint: orphaned: parent is gone; reap apply --override-manual asks a hardened confirm
KEEP 4 dirs 96.5 GB   (held or protected: holds expire in 12d, 30d; ...)
SAFE 145 dirs 7.9 GB   ready to reap: reap plan, then reap apply
sizes are logical; hardlinked content may reclaim less (zig lane cache shares bytes)
quarantine holds 3.4 GB, oldest 12d (reap quarantine prune)
```

Order: ACTIVE, BLOCKED, MANUAL, KEEP, SAFE last as the payoff. Rows size-desc, paths
right-truncated with ellipsis, sections elide past 15 rows with "+N more, use --json". Every
BLOCKED row carries a resolve hint (push command or `reap discard`); every MANUAL row carries one
action verb; rows with shadowed facts carry the "(also: ...)" detail. Colors follow incoda's
NO_COLOR / pipe rules. Long scans print a stderr progress line after a few seconds,
suppressed with --json. Totals include the per-reasonCode count + GB breakdown.

## Data model

reasonCode enum (normative, single source; --include/--exclude validate against exactly this
list): active, incoda-live, jj-active, scratch-fresh, scratch-recent, scratch-idle, dirty-files,
stashes, unpushed-commits, unpushed-reflog, no-remote, open-pr, jj-unpushed, ignored-content,
remote-stale, jj-remote-stale, orphaned-worktree, orphaned-workspace, nested-repositories,
parent-of-live-children, unknown-kind, state-unreadable, facts-unavailable, gh-unavailable,
held-by-user, protected, clean-pushed. Class memberships (Deletion reachability): ignorance =
facts-unavailable, state-unreadable, remote-stale, jj-remote-stale, gh-unavailable, unknown-kind;
judgment = ignored-content, orphaned-worktree, orphaned-workspace, nested-repositories,
parent-of-live-children, scratch-recent. Each code has a one-line prose template in the renderer;
hints are computed from the full fact set, so no output advertises a gate the tool will refuse.

skipWhy is the closed skip-cause enum, the deletion-side sibling of reasonCode, used identically
in apply/discard --json skipped[{path, why}], the summary "<reasons>", and reap.log skip lines:
git-busy (index.lock at capture time), active-tripwire, in-use-probe, verdict-changed,
parent-of-live-children, ignorance-unreadable, snapshot-overcap. The same locked-index condition
is state-unreadable at scan time (a verdict fact) and git-busy at capture time (a skip cause).

```json
{
  "generated": "...", "roots": [{"path": "...", "dirs": 137, "sizeGB": 51.2}],
  "entries": [{
    "path": "C:\\temp\\muxc", "zone": "C:\\temp", "kind": "git-repo",
    "sizeBytes": 13864974512, "sizePartial": false, "lastActivity": "...", "ageDays": 6,
    "clampedFiles": 0, "verdict": "BLOCKED", "reasonCode": "dirty-files",
    "reason": "5 dirty, 2 untracked", "hint": "commit+push, or reap discard",
    "branch": "main", "origin": "git@github.com:...", "dirty": 5, "untracked": 2,
    "ignored": 0, "stashes": 0, "unpushed": 0, "unpushedReflogOnly": 0, "openPR": false,
    "lastIncoda": {"ago": "3d", "owner": "sess-7", "reason": "muxc type check"},
    "lineageGroup": null, "held": false, "downgradedBy": null
  }],
  "totals": {"activeGB": 23.8, "blockedGB": 51.2, "manualGB": 55.7, "keepGB": 96.5,
             "safeGB": 7.9, "reclaimableGB": 7.2, "sizes": "logical",
             "byReason": [{"code": "dirty-files", "dirs": 41, "sizeGB": 33.0}, "..."]}
}
```

`held` is exclusively the user-pin flag. `downgradedBy` names the tool whose unavailability
weakened the verdict. `reclaimableGB` is derived by the hardlink file-index dedupe pass over the
SAFE set (bounded; SAFE is small), null with the logical-only caveat when skipped; scan, plan and
apply must agree on the same dir set (tested). plan/apply/holds also accept --json; apply --json
carries the runId stamped on every audit line, with widened[] separate from planned[].

## incoda integration

Current lane.log contract (per queue, `%LOCALAPPDATA%\incoda\queues\<key>\lane.log`, append-only,
`2006-01-02 15:04:05` + `k=v`): events enqueue (pid slots cmd), acquire (pid cmd), release (pid rc
peak_mem cpu), plus reaped/giveup/kill/kill-request/force-release/reenter/config. Verified in
source: dir/reason/owner live only on the ephemeral ticket, deleted at release, and Queue.Logf
swallows write failures, so the log is best-effort history and reap's join treats it as such.

The one incoda PR: append `dir=` (always), `reason=` and `owner=` (when set, %q-quoted) to
enqueue/acquire/release lines, and `dur=` to release. Additive; old logs keep parsing. Until the
deployed incoda carries it, no attribution is possible (release lines carry neither cmd= nor
dir=, verified in source and in the deployed log; enqueue/acquire cmd substrings are not
dir-keyed), so old-format events are COUNTED and labeled weak in `reap activity`, every
actionable row (ACTIVE/BLOCKED/MANUAL) renders `last: no incoda record`, and doctor reports
the dir= coverage share. (Amends the
original interim-mode sentence, which promised release-line cmd-substring attribution the log
shape cannot deliver.) reap reimplements incoda's StateDir resolution
(INCODA_DIR > platform default) in ~30 lines rather than importing: no coupling. reap never
writes to incoda state.

## Config and state

Paths are Windows spellings; reap uses the incoda platform convention (LOCALAPPDATA / Library
/Application Support / XDG_STATE_HOME, overridable with REAP_DIR).

`%LOCALAPPDATA%\reap\config.json` (stdlib JSON, single writer, atomic temp-and-rename writes;
a leading UTF-8 BOM, PowerShell 5 Set-Content's habit, is tolerated on read; no TOML
dependency):
- roots, env vars expanded against the interactive user's profile (doctor prints the expanded
  list). Defaults as measured: C:\temp, C:\tmp, C:\wt, C:\zc, C:\src, %TEMP%, CODE\OSS,
  ~\source.
- protect: built-ins `**/OneDrive/**`, `**/AppData/Local/vigz/**`, `**/.cache/**`,
  `**/AppData/Local/wsl/**`, `**/Virtual Hard Disks/**`, `%TEMP%\claude\**`, primary checkouts
  (CODE\OSS\wintty, wintty-release, ghostty, sshore, CODE\deblasis.net) + user additions.
- thresholds: active-hours=48, scratch-manual-days=7, scratch-safe-days=21,
  remote-stale-hours=72, quarantine-cap-gb=2 (delta-priced), quarantine-retention-days=30 (the
  default for prune --older-than), quarantine-margin=2.5 (preflight multiplier),
  min-free-mb=256; exec budgets git=30s jj=30s gh=15s fetch=120s.
- gh=true, jj=true toggles.

Path discipline (holds, protect, --override-manual, lineage): canonicalize once at
ingest (filepath.Clean, separators normalized, case-folded on Windows, `\\?\` stripped for
matching, used for probe/rm); holds match on path-component boundaries. Table tests cover
mismatched case, trailing slashes, long-path forms. Network-volume roots are refused;
reparse-point candidate children verdict KEEP.

`%LOCALAPPDATA%\reap\state\`:
- apply.lock: exclusive kernel lockfile (incoda pattern, ported) held for the whole of apply,
  discard, and prune, and for hold/unhold; a second holder fails fast naming
  the holder PID (and runId when one is running), exit 122.
- Sizes are never cached: the size pass and the activity max-mtime come from ONE fused walk, and
  a sizes-only cache can never skip it (the walk it would skip is the one that computes the
  uncachable fact). Warm scans get their speed from the walk pool and the git fact caches; the
  sizecache.json file of earlier drafts was dropped as structurally dead.
- holds.json: {path, expires}.
- reap.log: JSONL, write-ahead, single-writer by construction (apply.lock). Intent line before
  each deletion, result after; skip lines with cause; session envelopes {event: envelope, runId,
  planned, deleted, skipped, freeBytesBefore, freeBytesAfter}; line shape {runId, ts, event,
  path, kind, sizeBytes, verdict, reasonCode, skipWhy, origin, branch, headSha, lastCommitTs, dirty,
  untracked, stashes, ignored, parentRepoPath, mode, ok, residue, quarantinePath (null when
  none)}. An event:'abort' line records a confirmed run stopped at a confirm-window gate
  (path + cause in residue) before any deletion; residue is also the free-text note channel
  on SKIP lines (refusal prose, vanished-under notes) - skipWhy stays enum-clean. Every deletion that is not clean-pushed (scratch, carve-out, ignored-content and
  nested-repositories widenings) adds a capped top-level manifest, so "gone" is never
  "contents unknown" on any judgment-path deletion. Append failure = hard abort.
  Size-based rotation (default 50 MB, envelopes kept intact, reap.log.1...); `reap log` reads
  active + all rotations oldest-first.
- quarantine\: discard bundles; listed and pruned by `reap quarantine`; retention 30d default;
  doctor reports total bytes and oldest bundle age.

## Safety rails

- Protected globs, holds, and reparse-point candidates beat every rule and every flag.
- Deletion reachability (second invariant): --include/--override-manual can never reach a
  BLOCKED-class fact or an unread ignorance-class fact; fault-injection tested.
- apply/discard/prune re-verify per path immediately before acting: fresh facts (cache bypassed,
  `git fetch --prune` under its own budget), fresh-walk activity tripwire <2h, rename in-use
  probe to a deterministic `<name>.reap-probing` sibling with `\\?\` paths; restore retried,
  restore failure = hard error naming the new path; doctor/apply heal strays first, never
  overwriting (parked as `<name>.reap-orphaned-<ts>`, surfaced).
- Quarantine capture is non-mutating (plumbing path above); refusal = dir untouched, literally;
  crash-after-capture is byte-identical with pre-capture `git status` equality (fixture); delta
  bundles carry base SHA + remote and are revalidated at list/prune time (at-risk marking), with
  a self-contained full-bundle fallback; `reap quarantine restore` is the first-class recovery
  path.
- Deletion order: lineage children before parents; parent with live children outside the set
  skipped (parent-of-live-children); contents before `.git`/`.jj`; jj deregistration before rm;
  partial deletions logged; discard uses the same path.
- apply/discard/prune never cross a reparse point and never delete a root itself, where
  'a root itself' means a configured root's own entry point; a configured root that is
  also a candidate row of an OUTER configured root (overlapping roots) is a child in
  that outer scan and deletes children-first like any candidate.
- Per-dir walk errors mark sizePartial=true and verdict MANUAL; a scan never aborts on one bad
  dir; totals report the error count.
- Every destructive run prints the plan (naming widened codes and counts), requires TTY-confirm
  or --yes, preflights free space, ends with the deleted/excluded/skipped summary, and uses the
  exit band.

## Agent policy (AGENT-RULE block, pinned content; ships in M2 with apply)

Ships with the repo, mirroring incoda's voice: agents may freely run scan, plan, holds, log,
activity, quarantine list, doctor, and may propose deletions by showing plan output. `apply`
(with or without --yes), `discard`, `--no-quarantine`, `quarantine prune`, and hold changes are
human decisions: an agent runs them only when the user asked in the current session, always shows
the plan first, and never schedules or chains them on its own. Bare `apply` without --yes in a
non-TTY context is refused by the tool itself (exit 121), `--no-quarantine` is TTY-only over
--yes (120), and prune carries the same confirmation choreography — the mechanical backstops for
this rule.

## Performance

One global worker pool (8) for size walks, a separate bounded pool (4) for git/jj facts; gh is one bounded fan-out per run (the two-phase shape above). Cold `git status` on very large clones is the real cost; run with `-c gc.auto=0` and
untracked-cache-friendly flags. At plan/apply/discard time a second pass over only the deletion set
dedupes files with link count > 1 by file index (GetFileInformationByHandle via x/sys), so the
user sees "logical X GB, expected reclaim ~Y GB". Targets: <3 min warm, <6 min cold.

## Testing

- Verdict matrix table tests over fixture repos: clean+pushed; dirty; untracked; unpushed;
  no remote; detached HEAD with commits; stash present (tip and older generations); gitignored
  content; stale remote-tracking (branch deleted remotely after squash-merge); linked worktree
  with alive parent; orphaned worktree; parent with live child (scan MANUAL) and both-clean
  family (apply unlocks); nested .git clone; jj colocated with jj-only changes; jj workspace
  orphaned; expired hold; case-mismatched hold; live incoda ticket; open-PR from a fork with
  upstream remote; open-PR with origin=upstream and fork secondary; walk error; future-dated
  file; reflog-only commits post-reset. Matrix-completeness: every fixture yields exactly one
  verdict.
- Fault injection (fake PATH shims): no path to SAFE, and no path to deletion (widening,
  override, apply) for BLOCKED-class facts or unread ignorance-class facts; index-lock
  interference at re-verify time asserts the override is refused, not raced.
- Parser goldens: lane.log old/new formats, quoted reasons, malformed lines; attribution join
  incl. enqueued-not-released with and without a live ticket; live-ticket probe against a
  byte-range lock at offset 2^62.
- Quarantine: discard dirty+untracked+ignored, restore, diff; crash-after-capture asserts
  pre-capture `git status` equality AND byte-identical tree (plus a large-content variant);
  small dirty worktree of a large parent under the cap; fresh-clone restore of unpushed-on-
  another-branch, reflog-only-post-reset, and colocated 3-unpushed-jj-changes (commits
  FETCHABLE from the bundle, not merely packed); locked ignored file abort; unborn HEAD;
  over-cap refusal dir-untouched; verify-failure refusal; rotation-boundary `reap log`
  completeness; log-line-to-bundle-to-restored-files walk; discard input refusals (held path,
  ACTIVE path, MANUAL path, parent with live child, nested-repo dir) each asserting the named
  refusal message; squash-merged-and-pruned repo asserts the unpushed split rendering;
  hint-vs-eligibility consistency across every shadowed combination; non-TTY
  `apply --yes --override-manual <orphaned>` refused (exit 121) and TTY carve-out deletion
  produces the plain-copy snapshot and manifest, restorable via `reap quarantine restore`
  (mode-dispatched) and diffed; plain-copy no-fit prompt differs from the with-snapshot prompt
  (mode=plain-copy-skipped-overcap); simulated disk-full during plain-copy asserts
  refusal-with-dir-untouched and no mode=plain-copy line; locked-file-during-copy abort;
  discard on an orphaned dir refuses with the pointed carve-out message; widened
  ignored-content and nested-repositories deletions carry the capped manifest; renamed-parent
  fixture asserts the stale-gitdir path is surfaced; tag-only-unpushed fresh-clone restore;
  restore refuses a non-empty --to PATH (exit 120, naming what is there) and names exact SHAs
  when the base is gone; unreachable-remote fixture asserts the unverified (not at-risk)
  rendering.
- Apply mechanics: write-ahead ordering, skip logging, session envelope, exit band, probe heal
  (never-overwrite), children-before-parents, parent-of-live-children skip, contents-before-.git,
  --override-manual refusals (KEEP, BLOCKED-class-shadowed, ignorance-class), free-space
  preflight, cache-bypassed re-verify, two-number discard summary math.
- Concurrency: two applies (second fails fast), discard racing apply (same path), prune racing
  apply, hold write during apply (fails fast).
- jj fixtures use a local bare remote; jj tests skip with a notice when jj is absent.
- No CI (GH Actions billing is dead on this account): `go test ./...` locally is the gate.

## Repo layout

```
cmd/reap/main.go        internal/cli/         dispatch (incoda keeps command wiring here)
internal/config/        config.json, defaults, env expansion, path canonicalization
internal/walk/          root enumeration, reparse-safe sizing, lastActivity (+future clamp)
internal/classify/      kind detection incl. jj-workspace-orphaned
internal/gitx/          status --ignored, stash, rev-list --all --reflog HEAD, fetch --prune, worktree ops, children
internal/jjx/           push-state revsets, op log recency, workspace forget, parent + children, export w/ bookmarks
internal/ghx/           one two-phase gh fan-out per run (search for bases + per-base pr list),
internal/incodalog/     StateDir resolver, lane.log parse, join over all events, live tickets (2^62)
internal/verdict/       matrix, lineage groups, holds/protect overlay, deletion reachability
internal/report/        table (mock above), JSON renderers
internal/applycmd/      plan resolution, re-verify, ordered deletion, write-ahead audit, lock
internal/quarantine/    non-mutating capture, incremental bundles, verify, list/prune
internal/lockfile/      ported incoda OS-lock pattern
README.md + AGENT-RULE.md
```

Sign commits Alessandro De Blasis <alex@deblasis.net>. Private repo: no Claude attribution, no
session trailers anywhere (standing rule). English, incoda-grade README.

## Known traps this design already accounts for

- Stale remote-tracking refs after squash-merge branch deletion: fetch --prune at apply,
  staleness demotion at scan.
- Detached HEADs, stashes, tags, no-remote repos, reflog-only commits: `rev-list --all --reflog
  HEAD --not --remotes` decomposed into branch-reachable vs reflog-only counts with separate
  reasonCodes and days-to-expiry; quarantine bundles pin every recoverable tip as a named
  refs/reap/* ref (bundles materialize refs, never reflogs — uniformly, including jj bookmarks).
- Gitignored-only local content: porcelain --ignored routes to MANUAL.
- Fork+upstream open PRs: author-scoped search joined on any-remote slug + branch.
- Parent repos holding only-copy commits for live children: parent-of-live-children MANUAL/skip,
  children enumerated even from broken parents; both-clean families unlock only when children
  are deleted in the same run.
- Nested repositories: detection routes MANUAL; discard refuses naming them (bundled capture is
  future work).
- Manual-tier shadowing of BLOCKED facts: deletion reachability gates on the full fact set;
  fault-injection tested.
- Hardlinked zig content: logical vs expected-reclaim measured, not disclaimed.
- OneDrive placeholders, reparse points, network roots: KEEP or refused.
- Temp\claude live scratchpads: protected wholesale; the stale-scratchpad flag is near-future.
- Orphaned worktrees/workspaces (only-copy risk): MANUAL always.
- Shared-lineage unpushed counts: grouped detail without breaking the reasonCode contract.
- NTFS dir-mtime staleness: walk-derived lastActivity everywhere, never cached.
- Future-dated files: clamped at ingest, count surfaced.
- Concurrent agents: state lock, write-ahead log, live-ticket scan, re-verify + tripwire.
- reap's own footprint: quarantine retention + prune (full destructive choreography) + doctor
  and scan-footer readouts, audit-log rotation with cross-rotation `reap log`, free-space
  preflights with a configured floor.
- Accepted residue (documented, surfaced at deletion time in plan rows and intent lines):
  submodules configured ignore=dirty/all hide nested dirty state from superproject porcelain
  (presence caught by nested-repo detection, internal state not); jj colocated discard recovers
  commits and files but not the op log or change-id mapping (an op-store snapshot alongside the
  bundle is a future nicety).

## Future (explicitly out of v1)

- Stale Temp\claude scratchpad flagging tied to ~/.claude/jobs liveness (near-future: it is the
  actual scratch mass).
- Bundled capture of nested repositories inside discard.
- jj op-store snapshot for byte-perfect colocated discard recovery.
- Static HTML dashboard fed by scan --json history; scheduled history.jsonl for growth trends.
- incoda USN-window capture for stray-writer attribution outside known roots.
- Build-artifact purge inside kept repos.
- `reap why PATH` printing the full evidence trace for one dir.
