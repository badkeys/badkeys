import base64

from .checks import checkall, checkrsa


def _ub64toint(b64):
    fb64 = b64.replace(" ", "").encode()
    pad = b"=" * ((-len(fb64)) % 4)
    raw = base64.urlsafe_b64decode(fb64 + pad)
    return int.from_bytes(raw, byteorder="big")


def checkjwk(key, checks):
    r = {}
    if key["kty"] == "RSA":
        r["type"] = "rsa"
        r["n"] = _ub64toint(key["n"])
        r["e"] = _ub64toint(key["e"])
        r["results"] = checkrsa(r["n"], e=r["e"], checks=checks)
    elif key["kty"] == "EC":
        r["type"] = "ec"
        r["x"] = _ub64toint(key["x"])
        r["y"] = _ub64toint(key["x"])
        r["results"] = checkall(r["x"], checks=checks)
    elif key["kty"] == "OKP":
        r["type"] = "ec"
        r["x"] = _ub64toint(key["x"])
        # no y coordinate for ed25519/ed448
        r["results"] = checkall(r["x"], checks=checks)
    else:
        r["type"] = "unsupported"
        r["results"] = {}

    return r
