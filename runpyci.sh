#!/bin/bash
# SPDX-License-Identifier: 0BSD
# last update: 2026-10-23
# https://github.com/hannob/codingstyle
set -euo pipefail

PYLINTIG="consider-using-with,design,fixme,invalid-name,missing-docstring,modified-iterating-list,no-member,possibly-used-before-assignment,protected-access,too-many-lines,unused-argument,broad-exception-caught,c-extension-no-member,duplicate-code,global-statement,global-variable-not-assigned,import-error,import-outside-toplevel,inconsistent-return-statements,redefined-outer-name,unspecified-encoding"
RUFFIG="ANN,B909,B909,C90,CPY001,D,DOC402,FIX001,FIX002,FURB142,FURB142,ICN001,PLC2701,PLR0911,PLR0912,PLR0913,PLR0914,PLR0915,PLR0916,PLR0917,PLW0717,PLW1514,PTH,RUF102,RUF105,S314,S404,S405,S501,S603,SLF001,T201,TD002,TD003,B008,BLE001,COM812,FBT002,I001,N802,N806,PERF203,PERF401,PLC0415,PLC1901,PLR2004,PLW0602,PLW0603,PT009,RET505,RUF100,S202,S310,S607,S608,SIM102,SIM105,SIM108,SIM113,SIM114,SIM115,TD001,TD004,TRY300"

pyfind=$(find . -name \*.py)
pygrep=$(grep -rl --exclude-dir=.ruff_cache '^#!/usr/bin/python\|^#!/usr/bin/env python' . || true)
pyfiles=$(echo "$pyfind" "$pygrep" | sort -u)

pycodestyle --max-line-length=100 --ignore=W503,E203 $pyfiles
pyupgrade --py314-plus $pyfiles
pyflakes $pyfiles
flake8 --select=DUO --ignore=DUO107,DUO123,DUO131 $pyfiles
isort --line-length=100 --diff --check-only .
pylint --disable=$PYLINTIG $pyfiles
ruff check --preview --config 'output-prefer-rule-codes=true' \
	--line-length=100 --select=ALL --ignore=$RUFFIG \
	$pyfiles

if [ -e pyproject.toml ]; then
	pyproject check
	pyproject format --check
fi

if [ -d tests ]; then
	python -m unittest -v
fi
