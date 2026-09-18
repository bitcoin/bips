#!/bin/sh

# Check that mypy is available
check_availability() {
  command -v "$1" > /dev/null 2>&1 || {
    echo >&2 "$1 is required but it's not installed. Aborting."
    exit 1
  }
}

check_availability mypy
check_availability ruff

cd "$(dirname "$0")" || exit 1

status=0

# Run a command but do not exit on failure. Record that something failed.
run_keep() {
  "$@"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    status=1
  fi
  return 0
}

run_keep ruff check --quiet
run_keep ruff format --diff --quiet
run_keep mypy --no-error-summary .
run_keep mypy --no-error-summary --strict --untyped-calls-exclude=secp256k1lab -p chilldkg_ref --follow-imports=silent

run_keep python3 gen_vectors.py
run_keep python3 tests.py

exit $status
