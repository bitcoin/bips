#!/bin/sh

set -euo pipefail

check_availability() {
  command -v "$1" > /dev/null 2>&1 || {
    echo >&2 "$1 is required but it's not installed. Aborting.";
    exit 1;
  }
}

check_availability markdownlint-cli2
check_availability typos

markdownlint-cli2 ../bip-0445.md --config ./.markdownlint.json || true
typos ../bip-0445.md . || true

cd python || exit 1
./tests.sh
./example.py