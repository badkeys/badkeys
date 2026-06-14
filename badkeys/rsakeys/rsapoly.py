# SPDX-License-Identifier: MIT
# Copyright (c) Hanno Böck
#
# Part of badkeys: https://badkeys.info/

from .rsabias import _bitpct
from .smallfactors import smallfactors


def _checkbits(n, width, bitmask):
    # Skip the first chunk, it may contain larger
    # values due to next prime calculation
    _n = n >> width
    setbits = 0
    zerochunks = 0
    while _n:
        setbits |= _n & bitmask
        _n >>= width

        # check if the current chunk is zero
        if (((1 << width) - 1) & _n) == 0:
            zerochunks += 1

    if zerochunks >= 2:
        # if we see more than 1 zero chunk, we've
        # almost certainly hit a false positive
        return False

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
        return {"subtest": "completeftp", "biaspct": pct}

    return {"biaspct": pct}
