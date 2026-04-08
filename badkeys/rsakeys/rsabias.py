# SPDX-License-Identifier: MIT
# Copyright (c) Hanno Böck
#
# Part of badkeys: https://badkeys.info/
#
# Checks for unusual ratio of 0 and 1 bits in RSA modulus


from .smallfactors import smallfactors


def _bitpct(x):
    bitlen = x.bit_length()
    bitset = x.bit_count()
    return bitset * 100 // bitlen


def rsabias(n, e=0):  # noqa: ARG001
    pct = _bitpct(n)

    # For smaller keys, use a slightly larger threshold to
    # avoid false positives
    if n.bit_length() > 2000:
        threshold = 10
    elif n.bit_length() > 1000:
        threshold = 12
    else:
        threshold = 17

    if 50 - threshold < pct <= 50 + threshold:
        return False

    if smallfactors(n):
        # If we have small prime factors, report nothing
        # and leave it to the smallfactors module
        return False

    lowern = n % (1 << (n.bit_length() // 2))
    lowerpct = _bitpct(lowern)
    if 50 - threshold < lowerpct <= 50 + threshold:
        # No bias in the lower half of the modulus is a strong
        # indication of a "vanity" RSA key
        return {"subtest": "vanity", "biaspct": pct}

    return {"biaspct": pct}
