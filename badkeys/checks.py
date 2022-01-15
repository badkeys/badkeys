from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .rsakeys import fermat
from .rsakeys import smallfactors
from .rsakeys import roca

# List of available checks
allchecks = {
    "roca": {
        "type": "rsa",
        "function": roca,
        "desc": "Return of the Coopersmith Attack (ROCA) vulnerability",
    },
    "fermat": {
        "type": "rsa",
        "function": fermat,
        "desc": "Fermat factorization / close prime vulnerability",
    },
    "smallfactors": {
        "type": "rsa",
        "function": smallfactors,
        "desc": "Small prime factors (<=65537, usually corrupt)",
    },
}


def checkrsa(runchecks, n, e=65537):
    results = {}
    for check in runchecks:
        if allchecks[check]["type"] != "rsa":
            continue
        callcheck = allchecks[check]["function"]
        r = callcheck(n, e=e)
        if r is not False:
            results[check] = r
    return results


def checkpkey(rawkey, runchecks):
    key = load_pem_public_key(rawkey.encode())
    if isinstance(key, rsa.RSAPublicKey):
        n = key.public_numbers().n
        e = key.public_numbers().e
        return checkrsa(runchecks, n, e=e)
    print("non-RSA keys not implemented yet")


def checkcrt(rawcert, runchecks):
    crt = x509.load_pem_x509_certificate(rawcert.encode())
    if isinstance(crt.public_key(), rsa.RSAPublicKey):
        n = crt.public_key().public_numbers().n
        e = crt.public_key().public_numbers().e
        return checkrsa(runchecks, n, e=e)
    print("non-RSA keys not implemented yet")


def checkcsr(rawcsr, runchecks):
    csr = x509.load_pem_x509_csr(rawcsr.encode())
    if isinstance(csr.public_key(), rsa.RSAPublicKey):
        n = csr.public_key().public_numbers().n
        e = csr.public_key().public_numbers().e
        return checkrsa(runchecks, n, e=e)
    print("non-RSA keys not implemented yet")


def detectandcheck(inkey, userchecks):
    if "-----BEGIN CERTIFICATE-----" in inkey:
        return checkcrt(inkey, userchecks)
    elif "-----BEGIN CERTIFICATE REQUEST-----" in inkey:
        return checkcsr(inkey, userchecks)
    elif "-----BEGIN PUBLIC KEY-----" in inkey:
        return checkpkey(inkey, userchecks)
    elif "-----BEGIN RSA PUBLIC KEY-----" in inkey:
        return checkpkey(inkey, userchecks)
