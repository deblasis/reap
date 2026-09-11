#!/bin/sh
# Builds the fixed-path sandbox the demo tapes record from: /tmp/reap-tape.
# Same world as demo/demo.sh (held scratch, recent scratch, clean-pushed
# repo, dirty repo), minus the lifecycle commands - the tapes type those.
set -eu

root=/tmp/reap-tape
world="$root/world"; state="$root/state"; inc="$root/incoda"
rm -rf "$root"
mkdir -p "$world" "$state" "$inc"

days_ago() {
  date -v-"$1"d +%Y%m%d0000 2>/dev/null || date -d "$1 days ago" +%Y%m%d0000
}
age() {
  stamp="$(days_ago "$2")"
  find "$1" -exec touch -t "$stamp" {} +
}

# sparse multi-GB artifacts: apparent size carries the demo, disk pays ~0
mkfake() { # mkfake <path> <GB>
  dd if=/dev/zero of="$1" bs=1M count=0 seek="$(( $(echo "$2" | awk '{printf "%d", $1 * 1024}') ))" 2>/dev/null
}
mkdir -p "$world/scratch-old/target" "$world/scratch-recent"
mkfake "$world/scratch-old/target/artifact.bin" 3.4
mkfake "$world/scratch-recent/partial.bin" 1.2
age "$world/scratch-old" 40
age "$world/scratch-recent" 12

git init -q -b main "$world/clean-repo"
git -C "$world/clean-repo" -c user.name=demo -c user.email=demo@demo \
  commit -q --allow-empty -m shipped
git init -q --bare -b main "$root/clean.git"
git -C "$world/clean-repo" remote add origin "$root/clean.git"
git -C "$world/clean-repo" push -q origin main
# a committed 2.2 GB zeros artifact: compresses to ~nothing in the object
# store, the working-tree copy stays sparse for the walk
mkdir -p "$world/clean-repo/artifacts"
mkfake "$world/clean-repo/artifacts/build.bin" 2.2
git -C "$world/clean-repo" add -A
git -C "$world/clean-repo" -c user.name=demo -c user.email=demo@demo \
  commit -q -m artifact
git -C "$world/clean-repo" push -q origin main
git -C "$world/clean-repo" fetch -q origin
age "$world/clean-repo" 40
touch -t "$(days_ago 2)" "$world/clean-repo/.git/FETCH_HEAD"

git init -q -b main "$world/dirty-repo"
echo 'the only copy of something important' > "$world/dirty-repo/work-in-progress.txt"
git -C "$world/dirty-repo" add -A
git -C "$world/dirty-repo" -c user.name=demo -c user.email=demo@demo \
  commit -q -m base
git init -q --bare -b main "$root/dirty.git"
git -C "$world/dirty-repo" remote add origin "$root/dirty.git"
git -C "$world/dirty-repo" push -q origin main
echo 'uncommitted edits - the only copy' > "$world/dirty-repo/work-in-progress.txt"
mkfake "$world/dirty-repo/dataset.bin" 1.1
age "$world/dirty-repo" 40

cat > "$state/config.json" <<EOF
{
  "roots": ["$world"],
  "protect": [],
  "thresholds": {"active-hours": 48, "scratch-manual-days": 7, "scratch-safe-days": 21,
    "remote-stale-hours": 72, "quarantine-cap-gb": 2, "quarantine-retention-days": 30,
    "quarantine-margin": 2.5, "min-free-mb": 256,
    "git-budget": "30s", "jj-budget": "30s", "gh-budget": "15s", "fetch-budget": "120s"},
  "gh": true,
  "jj": true
}
EOF

export REAP_DIR="$state" INCODA_DIR="$inc"
# the hold must come AFTER the export: it writes into the sandbox state
# (standalone sources of this file start with no REAP_DIR at all)
"$DEMO_REAP" hold "$world/scratch-old" >/dev/null

# env.sh is what a recorded shell sources to point reap at this sandbox
# (rewritten on every run because the rm -rf above takes it with the world)
cat > "$root/env.sh" <<EOF
export REAP_DIR="$state" INCODA_DIR="$inc"
export PATH="$HOME/bin:\$PATH"
export PS1='\$ '
if [ -f "\${GH_TOKEN_FILE:-/nonexistent}" ]; then export GH_TOKEN="\$(cat "\$GH_TOKEN_FILE")"; fi
EOF
