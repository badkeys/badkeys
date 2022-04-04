#!/bin/bash
set -euo pipefail

wget -P badkeys/keydata https://badkeys.info/bldata/blocklist.dat.xz
xz -vd badkeys/keydata/blocklist.dat.xz
