#!/bin/sh

set -e

cd "$(dirname "$0")"
mypy --no-error-summary reference.py
python3 reference.py
python3 gen_vectors_helper.py > /dev/null
