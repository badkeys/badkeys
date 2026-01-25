import re

# Find suspicious patterns of 16 repeating bytes
_bprex = re.compile(rb"(.)\1{15}")


def pattern(n, e=0):  # noqa: ARG001
    nbin = n.to_bytes((n.bit_length() + 7) // 8)
    if _bprex.search(nbin):
        return {"detected": True}
    return False
