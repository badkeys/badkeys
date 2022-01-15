# License: MIT
# Copyright (c) 2017, CRoCS, EnigmaBridge Ltd.
# Copyright (c) 2022, Hanno Böck
#
# Original: https://github.com/crocs-muni/roca
# Reduced to core functionality by Hanno Böck

import gmpy2


def roca(element, e=0):
    generator = 65537
    generator_order = 2454106387091158800
    pp = [16, 81, 25, 7, 11, 13, 17, 23, 29, 37, 41, 53, 83]
    modulus = 0x924cba6ae99dfa084537facc54948df0c23da044d8cabe0edd75bc6
    if element <= 2:
        return False
    if gmpy2.powmod(element, generator_order, modulus) != 1:
        return False

    for prime_to_power in pp:
        order_div_prime_power = generator_order // prime_to_power
        g_dash = gmpy2.powmod(generator, order_div_prime_power, modulus)
        h_dash = gmpy2.powmod(element, order_div_prime_power, modulus)
        found = False
        for i in range(0, prime_to_power):
            if gmpy2.powmod(g_dash, i, modulus) == h_dash:
                found = True
                break
        if not found:
            return False
    return {"detected": True}
