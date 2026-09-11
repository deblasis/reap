#!/bin/sh
# A self-contained reap demo: builds a sandbox world, then walks the whole
# lifecycle - scan, plan, holds, apply, discard, quarantine restore, log.
#
# Everything happens inside one sandbox directory (world + state + incoda
# dir); nothing on the machine is configured, scanned or deleted.
#
# usage: sh demo/demo.sh [path-to-reap]     (default: reap on PATH)
#
# The sandbox world:
#   scratch-old     an idle scratch dir, held by you (KEEP: beats everything)
#   scratch-recent  a newer scratch dir (judgment call, not auto-deleted)
#   clean-repo      a git repo, committed and pushed (the easy SAFE case)
#   dirty-repo      a git repo with uncommitted work (BLOCKED: yours)
set -eu

REAP="${1:-reap}"

demo="$(mktemp -d "${TMPDIR:-/tmp}/reap-demo-XXXXXX")"
# On Windows the binary is a native exe: hand it Windows-shaped paths (Git
# Bash's /tmp is invisible to it); on macOS and Linux the path already is.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) demo="$(cygpath -m "$demo")" ;;
esac
world="$demo/world"; state="$demo/state"; inc="$demo/incoda"
mkdir -p "$world" "$state" "$inc"
cleanup() { rm -rf "$demo"; }
[ "${REAP_DEMO_KEEP:-}" ] || trap cleanup EXIT

# A timestamp N days ago, portable across BSD and GNU date.
days_ago() {
  date -v-"$1"d +%Y%m%d0000 2>/dev/null || date -d "$1 days ago" +%Y%m%d0000
}

age() { # age <dir> <days>
  stamp="$(days_ago "$2")"
  find "$1" -exec touch -t "$stamp" {} +
}

step() { printf '\n\033[36m=== %s\033[0m\n' "$1"; }
run() { printf '\n> %s\n' "$*"; "$@"; }

# --- the sandbox ----------------------------------------------------------

# sparse multi-GB artifacts: the apparent size carries the demo (the table
# and the summaries show GB), the disk pays almost nothing
mkfake() { # mkfake <path> <GB>
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      # NTFS: fsutil createnew sets the size without writing data (dd seek=
      # allocates real bytes there and drains the disk)
      fsutil file createnew "$(cygpath -w "$1")" \
        "$(( $(echo "$2" | awk '{printf "%d", $1 * 1024 * 1024 * 1024}') ))" >/dev/null ;;
    *)
      dd if=/dev/zero of="$1" bs=1M count=0 \
        seek="$(( $(echo "$2" | awk '{printf "%d", $1 * 1024}') ))" 2>/dev/null ;;
  esac
}
mkdir -p "$world/scratch-old/target" "$world/scratch-recent"
mkfake "$world/scratch-old/target/artifact.bin" 3.4
mkfake "$world/scratch-recent/partial.bin" 1.2
age "$world/scratch-old" 40
age "$world/scratch-recent" 12

# a clean, pushed repo: the easy SAFE case
git init -q -b main "$world/clean-repo"
git -C "$world/clean-repo" -c user.name=demo -c user.email=demo@demo \
  commit -q --allow-empty -m shipped
git init -q --bare -b main "$demo/clean.git"
git -C "$world/clean-repo" remote add origin "$demo/clean.git"
git -C "$world/clean-repo" push -q origin main
# a committed 2.2 GB artifact: zeros, so the object store compresses it to
# almost nothing while the working-tree copy (sparse) keeps the walk honest
mkdir -p "$world/clean-repo/artifacts"
mkfake "$world/clean-repo/artifacts/build.bin" 2.2
git -C "$world/clean-repo" add -A
git -C "$world/clean-repo" -c user.name=demo -c user.email=demo@demo \
  commit -q -m artifact
git -C "$world/clean-repo" push -q origin main
git -C "$world/clean-repo" fetch -q origin
age "$world/clean-repo" 40
# the fetch marker sits inside the freshness window: the remote state counts
touch -t "$(days_ago 2)" "$world/clean-repo/.git/FETCH_HEAD"

# a repo with uncommitted work: BLOCKED, and the discard + quarantine story
git init -q -b main "$world/dirty-repo"
echo 'the only copy of something important' > "$world/dirty-repo/work-in-progress.txt"
git -C "$world/dirty-repo" add -A
git -C "$world/dirty-repo" -c user.name=demo -c user.email=demo@demo \
  commit -q -m base
git init -q --bare -b main "$demo/dirty.git"
git -C "$world/dirty-repo" remote add origin "$demo/dirty.git"
git -C "$world/dirty-repo" push -q origin main
echo 'uncommitted edits - the only copy' > "$world/dirty-repo/work-in-progress.txt"
mkfake "$world/dirty-repo/dataset.bin" 1.1
age "$world/dirty-repo" 40

# reap's config: one root, no protect list, defaults
worldfwd="${world}" # config takes forward slashes
cat > "$state/config.json" <<EOF
{
  "roots": ["$worldfwd"],
  "protect": [],
  "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21,
    "remote-stale-hours": 72, "quarantine-cap-gb": 2, "quarantine-retention-days": 30,
    "quarantine-margin": 2.5, "min-free-mb": 256,
    "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"},
  "gh": true,
  "jj": true
}
EOF

REAP_DIR="$state" INCODA_DIR="$inc"
export REAP_DIR INCODA_DIR

# you pinned this one: it must beat every rule from the first scan on
"$REAP" hold "$world/scratch-old" >/dev/null

printf 'reap demo\nsandbox:  %s\nbinary:   %s\n' "$demo" "$("$REAP" version)"

step 'scan - what exists, and what each dir is'
run "$REAP" scan

step 'plan - exactly what a plain apply would delete (the SAFE set only)'
run "$REAP" plan

step 'holds - releasing the pin lets the dir back into the plan'
run "$REAP" holds
run "$REAP" unhold "$world/scratch-old"
run "$REAP" plan

step 'apply - delete the SAFE set, with the write-ahead audit trail'
run "$REAP" apply --yes

step 'discard - resolve a BLOCKED dir: quarantine it, then delete'
run "$REAP" discard "$world/dirty-repo" --yes

step 'quarantine list - what recovery exists, and how it is doing'
run "$REAP" quarantine list

step 'quarantine restore - prove the recovery is real (the dirty edits come back)'
sess="$(ls -t "$state/quarantine" | head -1)"
run "$REAP" quarantine restore "$sess" --to "$demo/recovered"
printf '\nrecovered file says: '
cat "$demo/recovered/work-in-progress.txt"

step 'log - every decision reap made, write-ahead, one line per event'
run "$REAP" log

if [ "${REAP_DEMO_KEEP:-}" ]; then printf '\nsandbox kept at %s\n' "$demo"; fi
exit 0
