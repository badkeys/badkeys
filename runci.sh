#!/bin/bash
set -euo pipefail

./badkeys-cli --update-bl

# linters etc.
pycodestyle --max-line-length=88 --ignore=W503,E203 badkeys-cli .
pyflakes .
pyupgrade --py311-plus badkeys-cli $(find -name \*.py)
black --check --diff .

# security checks
flake8 --select=DUO badkeys-cli .

# run tests
PYTHONWARNINGS=e python -m unittest
