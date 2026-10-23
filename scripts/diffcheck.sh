#!/bin/bash

tmpdir=$(mktemp -d) || exit 1
trap 'rm -rf "$tmpdir"' EXIT

scripts/buildtable.pl >"$tmpdir/table.mediawiki" 2> /dev/null || exit 1
diff README.mediawiki "$tmpdir/table.mediawiki" | grep '^[<>] |' >"$tmpdir/after.diff" || true
newdiff=$(diff -s scripts/diffcheck.expected "$tmpdir/after.diff" -u | grep '^[-+]')
if [ -n "$newdiff" ]; then
    echo "$newdiff"
    exit 1
fi
echo "README table matches expected table from BIP files"
