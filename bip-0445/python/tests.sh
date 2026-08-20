#!/bin/sh
set -e

check_availability() {
  command -v "$1" > /dev/null 2>&1 || {
    echo >&2 "$1 is required but it's not installed. Aborting.";
    exit 1;
  }
}

check_availability mypy
check_availability ruff

cd "$(dirname "$0")"

# Keep going if a linter fails
ruff check --quiet || true
ruff format --diff --quiet || true
mypy --no-error-summary . || true
# Be more strict in the reference code
mypy --no-error-summary --strict --untyped-calls-exclude=secp256k1lab -p frost_ref --follow-imports=silent || true

./gen_vectors.py
./tests.py
