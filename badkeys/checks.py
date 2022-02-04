from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .rsakeys import fermat
from .rsakeys import roca
from .rsakeys import smallfactors

# List of available checks
allchecks = {
    "fermat": {
        "type": "rsa",
        "function": fermat,
        "desc": "Fermat factorization / close prime vulnerability",
    },
    "roca": {
        "type": "rsa",
        "function": roca,
        "desc": "Return of the Coopersmith Attack (ROCA) vulnerability",
    },
    "smallfactors": {
        "type": "rsa",
        "function": smallfactors,
        "desc": "Small prime factors (<=65537, usually corrupt)",
    },
}


def checkrsa(n, e=65537, checks=allchecks.keys()):
    results = {}
    for check in checks:
        if allchecks[check]["type"] != "rsa":
            continue
        callcheck = allchecks[check]["function"]
        r = callcheck(n, e=e)
        if r is not False:
            results[check] = r
    return results


def checkpkey(rawkey, checks=allchecks.keys()):
    key = load_pem_public_key(rawkey.encode())
    r = {}
    if isinstance(key, rsa.RSAPublicKey):
        r["type"] = "rsa"
        r["n"] = key.public_numbers().n
        r["e"] = key.public_numbers().e
        r["bits"] = r["n"].bit_length()
        r["results"] = checkrsa(r["n"], e=r["e"], checks=checks)
        return r
    else:
        r["type"] = "unsupported"
    return r


def checkcrt(rawcert, checks=allchecks.keys()):
    crt = x509.load_pem_x509_certificate(rawcert.encode())
    r = {}
    if isinstance(crt.public_key(), rsa.RSAPublicKey):
        r["type"] = "rsa"
        r["n"] = crt.public_key().public_numbers().n
        r["e"] = crt.public_key().public_numbers().e
        r["bits"] = r["n"].bit_length()
        r["results"] = checkrsa(r["n"], e=r["e"], checks=checks)
    else:
        r["type"] = "unsupported"
    return r


def checkcsr(rawcsr, checks=allchecks.keys()):
    csr = x509.load_pem_x509_csr(rawcsr.encode())
    r = {}
    if isinstance(csr.public_key(), rsa.RSAPublicKey):
        r["type"] = "rsa"
        r["n"] = csr.public_key().public_numbers().n
        r["e"] = csr.public_key().public_numbers().e
        r["bits"] = r["n"].bit_length()
        r["results"] = checkrsa(r["n"], e=r["e"], checks=checks)
    else:
        r["type"] = "unsupported"
    return r


def detectandcheck(inkey, checks=allchecks.keys()):
    if "-----BEGIN CERTIFICATE-----" in inkey:
        return checkcrt(inkey, checks)
    elif "-----BEGIN CERTIFICATE REQUEST-----" in inkey:
        return checkcsr(inkey, checks)
    elif "-----BEGIN PUBLIC KEY-----" in inkey:
        return checkpkey(inkey, checks)
    elif "-----BEGIN RSA PUBLIC KEY-----" in inkey:
        return checkpkey(inkey, checks)
