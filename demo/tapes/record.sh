#!/bin/sh
# Records the three demo casts (built-in pty recorder) and converts them to GIFs
# with agg. Run from the repo root inside Linux/WSL; expects reap (linux)
# in ~/bin and the world built by demo/tapes/setup.sh (done below).
#
# Produces demo/casts/<name>.cast and img/demo-<name>.gif.
set -eu
cd "$(dirname "$0")/../.."
export PATH="$HOME/bin:$PATH"

# a monospace font for agg: installed into ~/.fonts by run-record.sh, so
# fontconfig resolves "JetBrains Mono" (agg takes families, not paths)

mkdir -p demo/casts img

# the typed-command scripts live OUTSIDE /tmp/reap-tape: setup.sh wipes that
# dir on every run (the env.sh lesson, one bug class over)
lines() { echo "demo/tapes/$1.lines"; }

export DEMO_REAP="$HOME/bin/reap"
. demo/tapes/setup.sh

record() { # record <name> <script-file>
  name="$1"; script="$2"
  # fresh world per cast: scan sees everything, apply has it all to delete,
  # discard still finds its dirty repo
  . demo/tapes/setup.sh
  {
    echo 'SLEEP 1'
    echo '. /tmp/reap-tape/env.sh && clear'
    cat "$script"
    echo 'SLEEP 2'
  } | python3 demo/tapes/record.py "demo/casts/$name.cast"
  "$HOME/bin/agg" --idle-time-limit 1.5 \
    "demo/casts/$name.cast" "img/demo-$name.gif"
  echo "== $name: $(wc -c < "img/demo-$name.gif") bytes"
}

cat > demo/tapes/scan.lines <<'EOF'
SLEEP 1
reap scan
SLEEP 9
EOF
cat > demo/tapes/apply.lines <<'EOF'
SLEEP 1
reap plan
SLEEP 9
reap unhold /tmp/reap-tape/world/scratch-old
SLEEP 1
reap plan
SLEEP 9
reap apply --yes
SLEEP 6
EOF
cat > demo/tapes/discard.lines <<'EOF'
SLEEP 1
reap discard /tmp/reap-tape/world/dirty-repo --yes
SLEEP 7
reap quarantine list
SLEEP 6
S=$(ls /tmp/reap-tape/state/quarantine)
reap quarantine restore $S --to /tmp/reap-tape/back
SLEEP 6
cat /tmp/reap-tape/back/work-in-progress.txt
SLEEP 2
EOF

record scan demo/tapes/scan.lines
record apply demo/tapes/apply.lines
record discard demo/tapes/discard.lines
