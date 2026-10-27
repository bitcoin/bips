#!/bin/sh

set -e

cd "$(dirname "$0")"
python3 tests/bip327-tests/test.py
python3 tests/multi-level-tests/test.py
python3 tests/multi-level-tests/random_tree_tests.py
