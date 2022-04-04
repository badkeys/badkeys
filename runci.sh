#!/bin/bash
set -euo pipefail

[ -e badkeys/keydata/blocklist.dat ] || ./getbl.sh

# linters etc.
pycodestyle --ignore=W503 badkeys-cli .
pyflakes .
pyupgrade --py311-plus badkeys-cli $(find -name \*.py)

# security checks
flake8 --select=DUO badkeys-cli .

# run tests
python -m unittest
