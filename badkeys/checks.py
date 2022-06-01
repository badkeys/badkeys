import hashlib
import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, dh
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.asymmetric import x448, ed448
from cryptography.hazmat.primitives import serialization

from .rsakeys import fermat
from .rsakeys import pattern
from .rsakeys import roca
from .rsakeys import rsainvalid
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
    "rsainvalid": {
        "type": "rsa",
        "function": rsainvalid,
        "desc": "RSA keys with invalid values",
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
        r["bits"] = key.key_size
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
        try:
            r["y"] = key.public_numbers().y
        except ValueError:
            # happens with e.g. very small (<512) DH keys
            return {"type": "unparseable", "results": {}}
        r["results"] = checkall(r["y"], checks=checks)
    else:
        r["type"] = "unsupported"
        r["results"] = {}
    spki = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    r["spkisha256"] = hashlib.sha256(spki).hexdigest()
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
    try:
        key = serialization.load_pem_public_key(rawkey.encode())
    except ValueError:
        # happens e.g. on partial inputs
        return {"type": "unparseable", "results": {}}
    return _checkkey(key, checks)


def checkprivkey(rawkey, checks=allchecks.keys()):
    try:
        priv = serialization.load_pem_private_key(rawkey.encode(), password=None)
    except ValueError:
        # happens on invalid values, e.g. p=q
        return {"type": "unparseable", "results": {}}
    except cryptography.exceptions.UnsupportedAlgorithm:
        # happens e.g. with unsupported curves
        return {"type": "unparseable", "results": {}}
    except TypeError:
        # happens on keys with passwords
        return {"type": "unparseable", "results": {}}
    return _checkkey(priv.public_key(), checks)


def checkcrt(rawcert, checks=allchecks.keys()):
    try:
        crt = x509.load_pem_x509_certificate(rawcert.encode())
    except (ValueError, cryptography.x509.base.InvalidVersion):
        return {"type": "unparseable", "results": {}}
    try:
        return _checkkey(crt.public_key(), checks)
    except cryptography.exceptions.UnsupportedAlgorithm:
        # happens e.g. with PSS keys
        return {"type": "unsupported", "results": {}}
    except (ValueError, NotImplementedError):
        # happens e.g. with ECDSA custom curves
        return {"type": "unsupported", "results": {}}


def checkcsr(rawcsr, checks=allchecks.keys()):
    csr = x509.load_pem_x509_csr(rawcsr.encode())
    return _checkkey(csr.public_key(), checks)


def checksshprivkey(sshkey, checks=allchecks.keys()):
    try:
        pkey = serialization.load_ssh_private_key(sshkey.encode(), password=None)
    except ValueError:
        # happens e.g. on password-protected keys
        return {"type": "unsupported", "results": {}}
    except cryptography.exceptions.UnsupportedAlgorithm:
        # happens e.g. on pre-standard sk-ssh-ed25519@openssh.com keys
        return {"type": "unsupported", "results": {}}
    return _checkkey(pkey.public_key(), checks)


def checksshpubkey(sshkey, checks=allchecks.keys()):
    try:
        pkey = serialization.load_ssh_public_key(sshkey.encode())
    except ValueError:
        # happens e.g. on non-standard DSA keys (!=1024 bit)
        return {"type": "unsupported", "results": {}}
    except cryptography.exceptions.UnsupportedAlgorithm:
        # happens e.g. on pre-standard sk-ssh-ed25519@openssh.com keys
        return {"type": "unsupported", "results": {}}
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
    elif "-----BEGIN OPENSSH PRIVATE KEY-----" in inkey:
        return checksshprivkey(inkey, checks)
    elif inkey.startswith("ssh-") or inkey.startswith("ecdsa-"):
        return checksshpubkey(inkey, checks)
    else:
        return {"type": "notfound", "results": {}}
