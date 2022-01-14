import gmpy2

MAX_PRIME = 65537

_smallprimes = None


def smallfactors(n, e=0):
    global _smallprimes

    # Generate product of all primes <= MAX_PRIME.
    # We calculate this once per program run, we could precalculate the
    # constant, but it's fast enough to calculate on the fly.
    if _smallprimes is None:
        sp = 2
        for i in range(3, MAX_PRIME + 1, 2):
            if gmpy2.is_prime(i):
                sp *= i
        _smallprimes = sp

    factor = gmpy2.gcd(_smallprimes, n)
    if factor != 1:
        return {"p": factor, "q": n // factor}
    return False
