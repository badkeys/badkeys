def rsawarnings(n, e=65537):
    bits = n.bit_length()

    # In theory, multiple warnings could apply, but badkeys
    # currently cannot represent this.
    # We start with the most severe, and go down from there.
    if bits < 768:
        return {"detected": True, "subtest": "extremely_small"}
    if bits < 2048:
        return {"detected": True, "subtest": "too_small"}
    if (bits % 8) != 0:
        return {"detected": True, "subtest": "not_multiple_of_8"}
    if bits not in [2048, 3072, 4096]:
        return {"detected": True, "subtest": "unusual_keysize"}

    if e == 3:
        return {"detected": True, "subtest": "exponent_3"}
    if e != 65537:
        return {"detected": True, "subtest": "exponent_not_65537"}

    return False
