import gmpy2


def rsainvalid(n, e=65537):
    if e < 3:
        return {"detected": True, "subtest": "invalid_e"}
    if gmpy2.is_prime(n):
        return {"detected": True, "subtest": "prime_n"}
    return False
