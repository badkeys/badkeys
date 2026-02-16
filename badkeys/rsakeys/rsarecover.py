# SPDX-License-Identifier: MIT
# Copyright (c) Hanno Böck

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def rsarecover(p=None, q=None, d=None, n=None, e=65537):
    try:
        if p and q:
            d = rsa.rsa_recover_private_exponent(e, p, q)
        elif d:
            p, q = rsa.rsa_recover_prime_factors(n, e, d)
        else:
            return None
        dmp1 = rsa.rsa_crt_dmp1(d, p)
        dmq1 = rsa.rsa_crt_dmq1(d, q)
        iqmp = rsa.rsa_crt_iqmp(p, q)
        pubnum = rsa.RSAPublicNumbers(e, n)
        privnum = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pubnum)
        privkey = privnum.private_key()
        pemprivate = privkey.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption())
    except ValueError:
        return None
    return pemprivate.decode("ascii")
