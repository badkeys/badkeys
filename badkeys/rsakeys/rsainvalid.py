import gmpy2


def rsainvalid(n, e=65537):
    if e < 3:
        return {"detected": True, "subtest": "invalid_e"}
    if e >= n:
        return {"detected": True, "subtest": "e_too_large"}
    if gmpy2.is_prime(n):
        return {"detected": True, "subtest": "prime_n"}
    return False
