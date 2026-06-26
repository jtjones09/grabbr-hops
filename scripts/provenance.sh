#!/usr/bin/env bash
# provenance.sh — KPI: how much of grabbr-hop is grabbr-authored vs inherited
# from upstream lan-mouse, by CURRENT Rust LOC (git blame).
#
# A line counts as grabbr-hop if its last-touching commit is post-fork (reachable
# from HEAD but not from the fork base); otherwise it is inherited lan-mouse code.
# This is "what's actually ours now", not churn — a rewritten file flips to ours.
#
# Run from anywhere in the repo. Requires the `upstream` remote (feschber/lan-mouse).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git fetch upstream --quiet 2>/dev/null || true
BASE=$(git merge-base HEAD upstream/main)
TMP=$(mktemp)
git rev-list "$BASE..HEAD" > "$TMP"   # the post-fork (grabbr-hop) commits

measure() { # $1 = path (a dir, or "." for everything)
  git ls-files "$1" | grep '\.rs$' \
    | while IFS= read -r f; do git blame --line-porcelain -- "$f" 2>/dev/null; done \
    | grep -E '^[0-9a-f]{40} ' | cut -d' ' -f1 \
    | awk -v set="$TMP" '
        BEGIN { while ((getline c < set) > 0) g[c]=1 }
        { t++; if ($1 in g) a++ }
        END { if (t>0) printf "%6d / %-6d  %3d%% ours\n", a, t, a*100/t; else print "          (no rust)" }'
}

echo "grabbr-hop provenance — current Rust LOC by authorship (fork base $(git rev-parse --short "$BASE"))"
echo
printf "  %-20s " "OVERALL"; measure "."
echo
for d in src input-capture input-emulation input-event lan-mouse-proto lan-mouse-ipc lan-mouse-cli lan-mouse-gtk; do
  printf "  %-20s " "$d"; measure "$d"
done
rm -f "$TMP"
