import base64
import binascii

from .checks import checkall, checkrsa

# See https://www.iana.org/assignments/jose/jose.xhtml
VALIDCURVES = ["P-256", "P-384", "P-521", "Ed25519", "Ed448", "X25519", "X448", "secp256k1"]


def _ub64toint(b64):
    fb64 = b64.replace(" ", "").encode()
    pad = b"=" * ((-len(fb64)) % 4)
    raw = base64.urlsafe_b64decode(fb64 + pad)
    return int.from_bytes(raw, byteorder="big")


def checkjwk(key, checks):
    r = {}
    try:
        if "kty" not in key:
            r["type"] = "unparseable"
            r["results"] = {}
            return r
        if key["kty"] == "RSA":
            if "n" not in key or "e" not in key or key["n"] == "" or key["e"] == "":
                r["type"] = "unparseable"
                r["results"] = {}
                return r
            r["type"] = "rsa"
            r["n"] = _ub64toint(key["n"])
            r["e"] = _ub64toint(key["e"])
            r["bits"] = r["n"].bit_length()
            r["results"] = checkrsa(r["n"], e=r["e"], checks=checks)
        elif key["kty"] == "EC":
            if "x" not in key or "y" not in key or key["x"] == "" or key["y"] == "" \
               or "crv" not in key or key["crv"] not in VALIDCURVES:
                r["type"] = "unparseable"
                r["results"] = {}
                return r
            r["type"] = "ec"
            r["curve"] = key["crv"].lower().replace("-", "")
            r["x"] = _ub64toint(key["x"])
            r["y"] = _ub64toint(key["x"])
            r["results"] = checkall(r["x"], checks=checks)
        elif key["kty"] == "OKP":
            if "x" not in key or key["x"] == "" \
               or "crv" not in key or key["crv"] not in VALIDCURVES:
                r["type"] = "unparseable"
                r["results"] = {}
                return r
            r["type"] = "ec"
            r["curve"] = key["crv"].lower()
            r["x"] = _ub64toint(key["x"])
            # no y coordinate for ed25519/ed448
            r["results"] = checkall(r["x"], checks=checks)
        else:
            r["type"] = "unsupported"
            r["results"] = {}
    except (binascii.Error, UnicodeEncodeError):
        r["type"] = "unparseable"
        r["results"] = {}
    return r
