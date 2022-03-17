from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, x448
from cryptography.hazmat.primitives import serialization

from .rsakeys import fermat
from .rsakeys import pattern
from .rsakeys import roca
from .rsakeys import sharedprimes
from .rsakeys import smallfactors
from .allkeys import ecbl
from .allkeys import rsabl

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
    "ecbl": {
        "type": "ec",
        "function": ecbl,
        "desc": "Elliptic curve x value blocklist",
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
    elif isinstance(key, ec.EllipticCurvePublicKey):
        r["type"] = "ec"
        r["x"] = key.public_numbers().x
        r["y"] = key.public_numbers().y
        r["results"] = checkec(r["x"], y=r["y"], checks=checks)
    elif (
        isinstance(key, ed25519.Ed25519PublicKey)
        or isinstance(key, x25519.X25519PublicKey)
        or isinstance(key, x448.X448PublicKey)
    ):
        r["type"] = "ec"
        # For Ed25519 the raw key is the x coordinate
        r["x"] = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        # we don't need the y coordinate
        r["results"] = checkec(r["x"], y=False, checks=checks)
    else:
        r["type"] = "unsupported"
        r["results"] = {}
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


def checkec(x, y=0, checks=allchecks.keys()):
    results = {}
    for check in checks:
        if allchecks[check]["type"] != "ec":
            continue
        callcheck = allchecks[check]["function"]
        r = callcheck(x, y=y)
        if r is not False:
            results[check] = r
    return results


def checkpubkey(rawkey, checks=allchecks.keys()):
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


def checksshpubkey(sshkey, checks=allchecks.keys()):
    pkey = serialization.load_ssh_public_key(sshkey.encode())
    return _checkkey(pkey, checks)


def detectandcheck(inkey, checks=allchecks.keys()):
    if "-----BEGIN CERTIFICATE-----" in inkey:
        return checkcrt(inkey, checks)
    elif "-----BEGIN CERTIFICATE REQUEST-----" in inkey:
        return checkcsr(inkey, checks)
    elif "-----BEGIN PUBLIC KEY-----" in inkey:
        return checkpubkey(inkey, checks)
    elif "-----BEGIN RSA PUBLIC KEY-----" in inkey:
        return checkpubkey(inkey, checks)
    elif "-----BEGIN PRIVATE KEY-----" in inkey:
        return checkprivkey(inkey, checks)
    elif "-----BEGIN RSA PRIVATE KEY-----" in inkey:
        return checkprivkey(inkey, checks)
    elif inkey.startswith("ssh-") or inkey.startswith("ecdsa-"):
        return checksshpubkey(inkey, checks)
