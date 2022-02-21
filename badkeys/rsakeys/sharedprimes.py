import gmpy2
from importlib.resources import open_binary

_moduli = {}

_supported_bits = [512, 768, 1024, 2048, 4096]


def sharedprimes(n, e=0):
    global _moduli
    bits = n.bit_length()
    if bits not in _supported_bits:
        return False

    if bits not in _moduli:
        with open_binary("badkeys.keydata", f"primes{bits}.dat") as f:
            _moduli[bits] = gmpy2.from_binary(f.read())

    breakme = gmpy2.gcd(n, _moduli[bits])
    if breakme == 1:
        return False
    # FIXME: Try to factor
    return {"detected": True}
