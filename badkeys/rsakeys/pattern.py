import re

# Find suspicious patterns of 16 repeating bytes
_prex = re.compile(r"(..)\1{15}")


def pattern(n, e=0):
    r = _prex.search(f"{n:02x}")
    if r:
        return {"detected": True}
    return False
