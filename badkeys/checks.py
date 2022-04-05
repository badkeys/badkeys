import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, dh
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.asymmetric import x448, ed448
from cryptography.hazmat.primitives import serialization

from .rsakeys import fermat
from .rsakeys import pattern
from .rsakeys import roca
from .rsakeys import sharedprimes
from .rsakeys import smallfactors
from .allkeys import blocklist

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
    "blocklist": {
        "type": "all",
        "function": blocklist,
        "desc": "Blocklists of compromised keys",
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
        r["results"] = checkall(r["x"], checks=checks)
    elif isinstance(key, dsa.DSAPublicKey):
        r["type"] = "dsa"
        r["y"] = key.public_numbers().y
        r["results"] = checkall(r["y"], checks=checks)
    elif (
        isinstance(key, ed25519.Ed25519PublicKey)
        or isinstance(key, x25519.X25519PublicKey)
        or isinstance(key, x448.X448PublicKey)
        or isinstance(key, ed448.Ed448PublicKey)
    ):
        r["type"] = "ec"
        # For Ed25519 the raw key is the x coordinate
        x_b = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        r["x"] = int.from_bytes(x_b, byteorder="big")
        # we don't need the y coordinate
        r["results"] = checkall(r["x"], checks=checks)
    elif isinstance(key, dh.DHPublicKey):
        r["type"] = "dh"
        r["y"] = key.public_numbers().y
        r["results"] = checkall(r["y"], checks=checks)
    else:
        r["type"] = "unsupported"
        r["results"] = {}
    return r


def checkrsa(n, e=65537, checks=allchecks.keys()):
    results = {}
    for check in checks:
        callcheck = allchecks[check]["function"]
        if allchecks[check]["type"] == "rsa":
            r = callcheck(n, e=e)
        elif allchecks[check]["type"] == "all":
            r = callcheck(n)
        else:
            continue
        if r is not False:
            results[check] = r
    return results


def checkall(x, checks=allchecks.keys()):
    results = {}
    for check in checks:
        if allchecks[check]["type"] != "all":
            continue
        callcheck = allchecks[check]["function"]
        r = callcheck(x)
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
    try:
        crt = x509.load_pem_x509_certificate(rawcert.encode())
    except ValueError:
        return {"type": "unparseable", "results": {}}
    try:
        return _checkkey(crt.public_key(), checks)
    except cryptography.exceptions.UnsupportedAlgorithm:
        # happens e.g. with PSS keys
        return {"type": "unsupported", "results": {}}
    except ValueError:
        # happens e.g. with ECDSA custom curves
        return {"type": "unsupported", "results": {}}

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
    elif "-----BEGIN DSA PRIVATE KEY-----" in inkey:
        return checkprivkey(inkey, checks)
    elif "-----BEGIN EC PRIVATE KEY-----" in inkey:
        return checkprivkey(inkey, checks)
    elif inkey.startswith("ssh-") or inkey.startswith("ecdsa-"):
        return checksshpubkey(inkey, checks)
