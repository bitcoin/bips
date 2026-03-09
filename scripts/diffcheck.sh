#!/bin/bash

scripts/buildtable.pl >/tmp/table.mediawiki 2> /dev/null
diff README.mediawiki /tmp/table.mediawiki | grep '^[<>] |' >/tmp/after.diff || true
newdiff=$(diff -s scripts/diffcheck.expected /tmp/after.diff -u | grep '^[-+]')
if [ -n "$newdiff" ]; then
    echo "$newdiff"
    exit 1
fi
echo "README table matches expected table from BIP files"
