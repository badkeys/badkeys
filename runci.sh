#!/bin/bash
set -euo pipefail

# linters etc.
pycodestyle --ignore=W503 badkeys-cli .
pyflakes .
pyupgrade --py311-plus badkeys-cli $(find -name \*.py)

# security checks
flake8 --select=DUO badkeys-cli .

# run tests
python -m unittest
