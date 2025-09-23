#!/bin/bash

set -Eeuo pipefail

after_diff="$(mktemp)"
before_diff="$(mktemp)"
table_current="$(mktemp)"
table_prev="$(mktemp)"

# Ensure previous commit is available (CI often uses shallow clones)
if ! git rev-parse --verify -q HEAD^ >/dev/null; then
	git fetch --deepen=100 >/dev/null 2>&1 || git fetch --unshallow >/dev/null 2>&1 || true
fi

# If previous commit is still unavailable, skip diff check gracefully
if ! git rev-parse --verify -q HEAD^ >/dev/null; then
	echo "Skipping diff check: previous commit (HEAD^) is unavailable in this environment"
	exit 0
fi

tmpdir="$(mktemp -d)"
cleanup() {
	git worktree remove --force "$tmpdir" >/dev/null 2>&1 || true
	rm -f "$table_current" "$table_prev" "$before_diff" "$after_diff" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Build table from current workspace
scripts/buildtable.pl >"$table_current" 2> /dev/null
diff README.mediawiki "$table_current" | grep '^[<>] |' >"$after_diff" || true

# Build table from previous commit using a detached worktree
if git worktree add --detach "$tmpdir" HEAD^ >/dev/null 2>&1; then
	(
		cd "$tmpdir"
		scripts/buildtable.pl >"$table_prev" 2>/dev/null
		diff README.mediawiki "$table_prev" | grep '^[<>] |' >"$before_diff" || true
	)
	newdiff=$(diff -s "$before_diff" "$after_diff" -u | grep '^\+')
	if [ -n "$newdiff" ]; then
		echo "$newdiff"
		exit 1
	fi
	echo "README table matches expected table from BIP files"
else
    echo 'Cannot build previous commit table for comparison'
    exit 1
fi
