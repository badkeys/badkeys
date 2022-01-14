import gmpy2

MAX_PRIME = 65537

smallprimes = None


def smallfactors(n, e=0):
    global smallprimes

    # Generate product of all primes <= MAX_PRIME.
    # We calculate this once per program run, we could precalculate the
    # constant, but it's fast enough to calculate on the fly.
    if smallprimes is None:
        smallprimes = 2
        for i in range(3, MAX_PRIME + 1, 2):
            if gmpy2.is_prime(i):
                smallprimes *= i

    factor = gmpy2.gcd(smallprimes, n)
    if factor != 1:
        return {"p": factor, "q": n // factor}
    return False
