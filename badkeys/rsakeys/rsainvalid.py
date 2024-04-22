def rsainvalid(n, e=65537):
    if e < 3:
        return {"detected": True, "subtest": "invalid_e"}
    if e >= n:
        return {"detected": True, "subtest": "e_too_large"}
    return False
