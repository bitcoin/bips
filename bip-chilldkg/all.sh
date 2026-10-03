#!/bin/sh

set -euo pipefail

./update-pydoc.sh

cd python || exit 1
./tests.sh
./example.py
