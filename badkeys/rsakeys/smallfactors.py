import functools

import gmpy2

MAX_PRIME = 65537


@functools.cache
def _gensmallprimes():
    # Generate product of all primes <= MAX_PRIME.
    # We calculate this once per program run, we could precalculate the
    # constant, but it's fast enough to calculate on the fly.
    sp = prime = 2
    while prime < MAX_PRIME:
        prime = gmpy2.next_prime(prime)
        sp *= prime
    return sp


def smallfactors(n, e=0):  # noqa: ARG001
    # Don't try to factor nonsensical keys
    if n <= 5:
        return False

    factor = gmpy2.gcd(_gensmallprimes(), n)
    if factor != 1:
        return {"p": int(factor), "q": int(n // factor)}
    return False
