from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from .rsakeys import fermat
from .rsakeys import pattern
from .rsakeys import roca
from .rsakeys import rsabl
from .rsakeys import sharedprimes
from .rsakeys import smallfactors

# List of available checks
allchecks = {
    "fermat": {
        "type": "rsa",
        "function": fermat,
        "desc": "Fermat factorization / close prime vulnerability",
    },
    "pattern": {
        "type": "rsa",
        "function": pattern,
        "desc": "Implausible repetition pattern in modulus",
    },
    "roca": {
        "type": "rsa",
        "function": roca,
        "desc": "Return of the Coopersmith Attack (ROCA) vulnerability",
    },
    "rsabl": {
        "type": "rsa",
        "function": rsabl,
        "desc": "RSA moduli blocklists",
    },
    "sharedprimes": {
        "type": "rsa",
        "function": sharedprimes,
        "desc": "Shared prime factors (batchgcd)",
    },
    "smallfactors": {
        "type": "rsa",
        "function": smallfactors,
        "desc": "Small prime factors (<=65537, usually corrupt)",
    },
}


def _checkkey(key, checks):
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
    key = serialization.load_pem_public_key(rawkey.encode())
    return _checkkey(key, checks)


def checkprivkey(rawkey, checks=allchecks.keys()):
    priv = serialization.load_pem_private_key(rawkey.encode(), password=None)
    return _checkkey(priv.public_key(), checks)


def checkcrt(rawcert, checks=allchecks.keys()):
    crt = x509.load_pem_x509_certificate(rawcert.encode())
    return _checkkey(crt.public_key(), checks)


def checkcsr(rawcsr, checks=allchecks.keys()):
    csr = x509.load_pem_x509_csr(rawcsr.encode())
    return _checkkey(csr.public_key(), checks)


def detectandcheck(inkey, checks=allchecks.keys()):
    if "-----BEGIN CERTIFICATE-----" in inkey:
        return checkcrt(inkey, checks)
    elif "-----BEGIN CERTIFICATE REQUEST-----" in inkey:
        return checkcsr(inkey, checks)
    elif "-----BEGIN PUBLIC KEY-----" in inkey:
        return checkpkey(inkey, checks)
    elif "-----BEGIN RSA PUBLIC KEY-----" in inkey:
        return checkpkey(inkey, checks)
    elif "-----BEGIN PRIVATE KEY-----" in inkey:
        return checkprivkey(inkey, checks)
    elif "-----BEGIN RSA PRIVATE KEY-----" in inkey:
        return checkprivkey(inkey, checks)
