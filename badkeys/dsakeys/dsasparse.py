# SPDX-License-Identifier: MIT
# Copyright (c) Hanno Böck
#
# Part of badkeys: https://badkeys.info/

def dsasparse(y, p=0):  # noqa: ARG001
    if p.bit_length() != 1024 or (p >> 1000) != 0x800000:
        return False
    p_ = p >> 168
    p_ ^= 1 << 855
    while p_:
        if p_ & 0x00fffff0 != 0:
            return False
        p_ >>= 32

    return {"detected": True}
