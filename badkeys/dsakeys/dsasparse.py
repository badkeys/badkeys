# SPDX-License-Identifier: MIT
# Copyright (c) Hanno Böck
#
# Part of badkeys: https://badkeys.info/

def dsasparse(y, p=0):  # noqa: ARG001
    if p.bit_length() != 1024 or (p >> 1000) != 0x800000 :
        return False
    _p = p >> 168
    _p ^= 1 << 855
    while _p:
        if _p & 0x00fffff0 != 0:
            return False
        _p >>= 32

    return {"detected": True}
