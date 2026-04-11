# SPDX-License-Identifier: MIT
# Copyright (c) Hanno Böck
#
# Part of badkeys: https://badkeys.info/

from .rsabias import _bitpct
from .smallfactors import smallfactors


def _checkbits(n, width, bitmask):
    _n = n
    setbits = 0
    while _n:
        # Skip the first chunk, it may contain larger
        # values due to next prime calculation
        _n >>= width
        setbits |= _n & bitmask
    return setbits == 0


def rsapoly(n, e=0):  # noqa: ARG001
    pct = _bitpct(n)
    if pct >= 40:
        return False

    # Detection may not work with implausibly small keys
    if n.bit_length() < 500:
        return False

    lowern = n % (1 << (n.bit_length() // 2))
    lowerpct = _bitpct(lowern)
    if lowerpct >= 40:
        # Probably vanity RSA key, not necessarily insecure,
        # handled by rsabias check
        return False

    if smallfactors(n):
        # If we have small prime factors, report nothing
        # and leave it to the smallfactors module
        return False

    if _checkbits(n, 128, 0xffffffffffff0000):
        # Use funny animal names as placeholders
        # for unidentified vulnerability subtypes
        return {"subtest": "nautilus", "biaspct": pct}
    if _checkbits(n, 32, 0x03ff00000):
        return {"subtest": "centipede", "biaspct": pct}

    return {"biaspct": pct}
