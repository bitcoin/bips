#!/bin/bash

# Create secure temporary directories and ensure cleanup
tmp_dir="$(mktemp -d)"; prev_dir="$(mktemp -d)"; trap 'rm -rf "$tmp_dir" "$prev_dir"' EXIT

# Paths for current commit artifacts
table_file="$tmp_dir/table.mediawiki"
after_diff="$tmp_dir/after.diff"
before_diff="$tmp_dir/before.diff"
table_prev_file="$tmp_dir/table_prev.mediawiki"

# Build table from current working tree and compute diff
scripts/buildtable.pl >"$table_file" 2>/dev/null
diff README.mediawiki "$table_file" | grep '^[<>] |' >"$after_diff" || true

# Build table from previous commit without altering the working tree
if git archive --format=tar HEAD^ | tar -x -C "$prev_dir" && perl "$prev_dir/scripts/buildtable.pl" >"$table_prev_file" 2>/dev/null; then
    diff "$prev_dir/README.mediawiki" "$table_prev_file" | grep '^[<>] |' >"$before_diff" || true
    newdiff=$(diff -s "$before_diff" "$after_diff" -u | grep '^+')
    if [ -n "$newdiff" ]; then
        echo "$newdiff"
        exit 1
    fi
    echo "README table matches expected table from BIP files"
else
    echo 'Cannot build previous commit table for comparison'
    exit 1
fi
