#!/bin/bash
# Re-exports the ledger experiment branch and docs into the POS repo branch and pushes.
set -eu
S=/tmp/claude-0/-home-user-wea-japan-pos-poc/8fb10d81-7d79-5e0b-88f5-274972519579/scratchpad
L=/home/user/midnightntwrk/midnight-ledger
P=/home/user/wea-japan-pos-poc
E="$P/experiments/regulated-zswap-csl"
MSG="${1:-Update regulated ZSwap CSL experiment artifacts}"
cd "$P" && git switch -q claude/exciting-carson-rz5qr5
mkdir -p "$E/plan" "$E/design" "$E/patches" "$E/scripts" "$E/results"
cp "$L/docs/experiments/regulated-zswap-csl/"*.md "$E/design/" 2>/dev/null || true
mv "$E/design/results.md" "$E/results/results.md" 2>/dev/null || true
rm -f "$E/patches"/*.patch
(cd "$L" && git format-patch -q fa995fa5791bc19112e97334a2d9265751c35fad..HEAD -o "$E/patches")
cp "$S"/stage*_chain*.sh "$S"/apply_*.py "$S/publish.sh" "$E/scripts/" 2>/dev/null || true
for f in "$S"/logs/*.log; do
  n=$(basename "$f" .log)
  grep -v '^\s*Compiling\|^\s*Downloading\|^\s*Downloaded\|^\s*Finished\|^\s*Running\|^\s*Blocking\|^warning\|^\s*|\|^\s*=\|-->\|^\s*$' "$f" | head -250 > "$E/results/$n.txt" || true
done
cd "$P" && git add experiments && git -c user.name="Jalal Hannan" -c user.email="jalal.hannan@midnight.foundation" commit -q -m "$MSG

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Q9CJgdhDhwqKR5eCeFM2VG" || echo "nothing to commit"
n=0; until git push -q -u origin claude/exciting-carson-rz5qr5 2>/dev/null; do n=$((n+1)); [ $n -ge 4 ] && { echo "push failed"; exit 1; }; sleep $((2**n)); done
git log --oneline -1
