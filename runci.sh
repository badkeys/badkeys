#!/bin/bash
set -euo pipefail

[ -e badkeys/keydata/blocklist.dat ] || ./getbl.sh

# linters etc.
pycodestyle --max-line-length=88 --ignore=W503,E203 badkeys-cli .
pyflakes .
pyupgrade --py311-plus badkeys-cli $(find -name \*.py)

# security checks
flake8 --select=DUO badkeys-cli .

# run tests
python -m unittest
