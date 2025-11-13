#!/bin/bash

set -euo pipefail

scripts/buildtable.pl >/tmp/table.mediawiki 2> /dev/null
diff README.mediawiki /tmp/table.mediawiki | grep '^[<>] |' >/tmp/after.diff || true

orig_branch=$(git symbolic-ref --short HEAD 2>/dev/null || true)
orig_head=$(git rev-parse HEAD)

cleanup() {
    if [[ -n "$orig_branch" ]]; then
        git checkout "$orig_branch" >/dev/null 2>&1 || git checkout "$orig_head" >/dev/null 2>&1
    else
        git checkout "$orig_head" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if git checkout HEAD^ >/dev/null 2>&1; then
    trap 'cleanup; exit 1' INT TERM HUP
    scripts/buildtable.pl >/tmp/table.mediawiki 2>/dev/null
    diff README.mediawiki /tmp/table.mediawiki | grep '^[<>] |' >/tmp/before.diff || true
    newdiff=$(diff -s /tmp/before.diff /tmp/after.diff -u | grep '^[+]')
    if [ -n "$newdiff" ]; then
        echo "$newdiff"
        exit 1
    fi
    echo "README table matches expected table from BIP files"
else
    echo 'Cannot build previous commit table for comparison'
    exit 1
fi
