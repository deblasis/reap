# Security policy

## Reporting

Email alex@deblasis.net with "reap security" in the subject. Include a
reproduction (commands, config, exit codes) and the reap version. Please do
not open public issues for anything you believe is exploitable.

## Scope

reap deletes directories. The security questions that matter, in order:

1. **Can anything reach a deletion it should not?** The core guarantees:
   no directory verdicts SAFE on stale, missing, or errored evidence, and no
   path carrying a BLOCKED-class fact is deletable by any flag combination
   except the one named orphaned carve-out, which requires a live TTY and a
   capped plain-copy snapshot first. Holds and protect globs beat every rule
   and every flag. Anything that looks like a bypass of these is critical.
2. **Untrusted verdict inputs.** reap parses output from git, jj, gh and
   incoda's lane.log, and reads config.json and holds.json from its state
   dir. Malformed or hostile input must degrade the verdict (weaken toward
   MANUAL/KEEP), never strengthen it, and must not crash the tool. A parse
   that yields a false SAFE is critical; a panic on hostile input is high.
3. **Audit and quarantine integrity.** The ledger is write-ahead: an intent
   line exists before every deletion, so a crash never leaves an unaudited
   deletion. Quarantine bundles must fail closed (a corrupt bundle never
   lists as verified). Tampering that could make a deletion unaudited or a
   corrupt bundle report healthy is high.
4. **Local, single-machine, single-user.** reap runs as you, on your
   machine, over directories you own. There is no service, no network
   listener, and no remote execution; the gh integration is read-only API
   polling. Network-adjacent attack surface is out of scope beyond what
   item 2 covers (a hostile or MITM'd gh response is just untrusted input).

## Threats explicitly out of scope

- Another user on the machine writing to your state directory (reap is not
  multi-user; if your TEMP or home is hostile, the tool cannot save you).
- Being pointed at directories whose contents lie (a repo whose git output
  claims "clean + pushed" because the remote it points at is attacker-
  controlled: reap verifies against the remotes you configured).
- Resource exhaustion (a huge tree making scans slow).

## Handling

Reports are triaged within a week. Fixes ship as patch releases; credits
welcome, bounty none (this is a personal project).
