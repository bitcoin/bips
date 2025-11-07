#!/bin/bash

scripts/buildtable.pl >/tmp/table.mediawiki 2> /dev/null
diff README.mediawiki /tmp/table.mediawiki | grep '^[<>] |' >/tmp/after.diff || true
ORIGINAL_HEAD=$(git rev-parse HEAD)
if git checkout HEAD^ && scripts/buildtable.pl >/tmp/table.mediawiki 2>/dev/null; then
    diff README.mediawiki /tmp/table.mediawiki | grep '^[<>] |' >/tmp/before.diff || true
    newdiff=$(diff -s /tmp/before.diff /tmp/after.diff -u | grep '^+')
    git checkout "$ORIGINAL_HEAD" >/dev/null 2>&1
    if [ -n "$newdiff" ]; then
        echo "$newdiff"
        exit 1
    fi
    echo "README table matches expected table from BIP files"
else
    git checkout "$ORIGINAL_HEAD" >/dev/null 2>&1
    echo 'Cannot build previous commit table for comparison'
    exit 1
fi
