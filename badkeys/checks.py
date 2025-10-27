import hashlib
import warnings

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa, x448, x25519

from .allkeys import blocklist
from .rsakeys import (fermat, pattern, roca, rsainvalid, rsawarnings, sharedprimes, smallfactors,
                      xzbackdoor)

# List of available checks
defaultchecks = {
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
    "xzbackdoor": {
        "type": "rsa",
        "function": xzbackdoor,
        "desc": "xz backdoor payload in RSA n",
    },
    "blocklist": {
        "type": "all",
        "function": blocklist,
        "desc": "Blocklists of compromised keys",
    },
}

warningchecks = {
    "rsawarnings": {
        "type": "rsa",
        "function": rsawarnings,
        "desc": "RSA key size and exponent warnings",
    },
}

allchecks = defaultchecks | warningchecks

# cryptography warns about SSH DSA keys being deprecated.
# For now, disable the warnings. Needs a better long-term solution.
warnings.filterwarnings(
    "ignore",
    category=cryptography.utils.CryptographyDeprecationWarning,
    module="badkeys.checks",
)


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
        r["curve"] = key.curve.name
        # shorter names for standard curves
        if r["curve"].startswith("sec") and r["curve"].endswith("r1"):
            r["curve"] = r["curve"][3:-2]
        r["x"] = key.public_numbers().x
        r["y"] = key.public_numbers().y
        r["results"] = checkall(r["x"], checks=checks)
    elif isinstance(key, dsa.DSAPublicKey):
        r["type"] = "dsa"
        r["y"] = key.public_numbers().y
        r["bits"] = key.key_size
        r["results"] = checkall(r["y"], checks=checks)
    elif isinstance(
        key,
        (
            ed25519.Ed25519PublicKey,
            x25519.X25519PublicKey,
            x448.X448PublicKey,
            ed448.Ed448PublicKey,
        ),
    ):
        r["type"] = "ec"
        r["curve"] = str(type(key).__name__).lower()[:-9]
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


def checkrsa(n, e=65537, checks=defaultchecks.keys()):
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


def checkall(x, checks=defaultchecks.keys()):
    results = {}
    for check in checks:
        if allchecks[check]["type"] != "all":
            continue
        callcheck = allchecks[check]["function"]
        r = callcheck(x)
        if r is not False:
            results[check] = r
    return results


def _reterr(rtype, ex):
    return {"type": rtype, "results": {}, "exception": ex.__class__.__name__, "errmsg": str(ex)}


def checkpubkey(rawkey, checks=defaultchecks.keys()):
    try:
        key = serialization.load_pem_public_key(rawkey.encode())
    except ValueError as e:
        # ValueError: defect inputs (partial keys, ASN.1 errors), ECDSA with explicit curves,
        #             unknown key types (e.g., ML-DSA)
        return _reterr("unparseable", e)
    except cryptography.exceptions.UnsupportedAlgorithm as e:
        # UnsupportedAlgorithm: Unsupported elliptic curves
        return _reterr("unsupported", e)
    return _checkkey(key, checks)


def checkprivkey(rawkey, checks=defaultchecks.keys()):
    try:
        priv = serialization.load_pem_private_key(rawkey.encode(), password=None)
    except ValueError as e:
        # ValueError: defect inputs, unknown key types, explicit curves
        return _reterr("unparseable", e)
    except (cryptography.exceptions.UnsupportedAlgorithm, TypeError) as e:
        # UnsupportedAlgorithm: Unsupported elliptic curves
        # TypeError: passwords-protected keys
        return _reterr("unsupported", e)
    return _checkkey(priv.public_key(), checks)


def checkcrt(rawcert, checks=defaultchecks.keys()):
    try:
        crt = x509.load_pem_x509_certificate(rawcert.encode())
    except (ValueError, cryptography.x509.base.InvalidVersion) as e:
        return _reterr("unparseable", e)
    try:
        pubkey = crt.public_key()
    except (cryptography.exceptions.UnsupportedAlgorithm, ValueError, NotImplementedError) as e:
        # ValueError: unknown key types, explicit curves
        # UnsupportedAlgorithm: unsupported curves
        # NotImplementedError: ? (possibly certificate extension issues)
        return _reterr("unsupported", e)
    return _checkkey(pubkey, checks)


def checkcsr(rawcsr, checks=defaultchecks.keys()):
    try:
        csr = x509.load_pem_x509_csr(rawcsr.encode())
    except (ValueError, cryptography.x509.base.InvalidVersion) as e:
        return _reterr("unparseable", e)
    try:
        pubkey = csr.public_key()
    except (cryptography.exceptions.UnsupportedAlgorithm, ValueError) as e:
        # ValueError: unknown key types, explicit curves
        # UnsupportedAlgorithm: unsupported curves
        return _reterr("unsupported", e)
    return _checkkey(pubkey, checks)


def checksshprivkey(sshkey, checks=defaultchecks.keys()):
    try:
        pkey = serialization.load_ssh_private_key(sshkey.encode(), password=None)
    except ValueError as e:
        # ValueError: defect keys
        return _reterr("unparseable", e)
    except (cryptography.exceptions.UnsupportedAlgorithm, TypeError) as e:
        # UnsupportedAlgorithm: unsupported key types, e.g., sk-*
        # TypeError: password-protected keys
        return _reterr("unsupported", e)
    return _checkkey(pkey.public_key(), checks)


def checksshpubkey(sshkey, checks=defaultchecks.keys()):
    try:
        pkey = serialization.load_ssh_public_key(sshkey.encode())
    except ValueError as e:
        # ValueError: defect keys, non-standard DSA keys (!=1024 bit)
        return _reterr("unparseable", e)
    except cryptography.exceptions.UnsupportedAlgorithm as e:
        # UnsupportedAlgorithm: unsupported key types
        return _reterr("unsupported", e)
    return _checkkey(pkey, checks)


def detectandcheck(inkey, checks=defaultchecks.keys()):
    if "-----BEGIN CERTIFICATE-----" in inkey:
        return checkcrt(inkey, checks)
    if "-----BEGIN CERTIFICATE REQUEST-----" in inkey:
        return checkcsr(inkey, checks)
    if "-----BEGIN PUBLIC KEY-----" in inkey:
        return checkpubkey(inkey, checks)
    if "-----BEGIN RSA PUBLIC KEY-----" in inkey:
        return checkpubkey(inkey, checks)
    if "-----BEGIN PRIVATE KEY-----" in inkey:
        return checkprivkey(inkey, checks)
    if "-----BEGIN RSA PRIVATE KEY-----" in inkey:
        return checkprivkey(inkey, checks)
    if "-----BEGIN DSA PRIVATE KEY-----" in inkey:
        return checkprivkey(inkey, checks)
    if "-----BEGIN EC PRIVATE KEY-----" in inkey:
        return checkprivkey(inkey, checks)
    if "-----BEGIN OPENSSH PRIVATE KEY-----" in inkey:
        return checksshprivkey(inkey, checks)
    if inkey.startswith(("ssh-", "ecdsa-")):
        return checksshpubkey(inkey, checks)
    return {"type": "notfound", "results": {}}
