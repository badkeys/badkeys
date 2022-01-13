import gmpy2


def fermat(n, e=65535):
    tries = 100

    a = gmpy2.isqrt(n)

    c = 0
    while not gmpy2.is_square(a ** 2 - n):
        a += 1
        c += 1
        if c > tries:
            return False
    bsq = a ** 2 - n
    b = gmpy2.isqrt(bsq)
    p = a + b
    q = a - b
    debugmsg = f"Fermat factorization after {c} rounds, b={b}"
    return {"p": p, "q": q, "debug": debugmsg}
