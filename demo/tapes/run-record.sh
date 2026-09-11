#!/bin/sh
# WSL runner: stage everything, strip CRLF, record + convert.
set -eu
R=/mnt/c/Users/ALESSA~1/CODE/reap
T=~/reap-taperepo
mkdir -p "$T"
cp -r "$R/demo" "$T"/
cp "$R"/img . 2>/dev/null || true
find "$T/demo" -type f | while read -r f; do sed -i 's/\r$//' "$f"; done
# font for agg: JetBrains Mono from the Windows zip
mkdir -p /tmp/reap-tape
python3 - <<'PY'
import zipfile, glob, shutil, os
z = glob.glob('/mnt/c/Users/Alessandro/JetBrainsMono.zip') + glob.glob('/mnt/c/Users/Alessandro/claude/JetBrainsMono.zip')
assert z, 'JetBrainsMono.zip not found'
with zipfile.ZipFile(z[0]) as zf:
    ttfs = [n for n in zf.namelist() if 'JetBrainsMonoNerdFont-Regular.ttf' in n]
    assert ttfs, 'regular ttf not in zip: %s' % zf.namelist()[:10]
    zf.extract(ttfs[0], '/tmp/reap-tape/font')
src = glob.glob('/tmp/reap-tape/font/**/*.ttf', recursive=True)[0]
shutil.copy(src, '/tmp/reap-demo-font.ttf')
PY
cp /mnt/c/Users/Alessandro/claude/_ghtoken.txt /tmp/reap-gh-token 2>/dev/null || true
export GH_TOKEN_FILE=/tmp/reap-gh-token
export DEMO_FONT=/tmp/reap-demo-font.ttf
cd "$T"
sh demo/tapes/record.sh
rm -f /tmp/reap-gh-token
