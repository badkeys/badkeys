import gmpy2

MAX_PRIME = 65537

_smallprimes = None


def smallfactors(n, e=0):  # noqa: ARG001
    global _smallprimes

    # Don't try to factor nonsensical keys
    if n <= 5:
        return False

    # Generate product of all primes <= MAX_PRIME.
    # We calculate this once per program run, we could precalculate the
    # constant, but it's fast enough to calculate on the fly.
    if _smallprimes is None:
        sp = prime = 2
        while prime < MAX_PRIME:
            prime = gmpy2.next_prime(prime)
            sp *= prime
        _smallprimes = sp

    factor = gmpy2.gcd(_smallprimes, n)
    if factor != 1:
        return {"p": int(factor), "q": int(n // factor)}
    return False
