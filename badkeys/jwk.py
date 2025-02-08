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
        if "n" not in key or "e" not in key or key["n"] == "" or key["e"] == "":
            r["type"] = "unparseable"
            r["results"] = {}
            return r
        r["type"] = "rsa"
        r["n"] = _ub64toint(key["n"])
        r["e"] = _ub64toint(key["e"])
        r["results"] = checkrsa(r["n"], e=r["e"], checks=checks)
    elif key["kty"] == "EC":
        if "x" not in key or "y" not in key or key["x"] == "" or key["y"] == "":
            r["type"] = "unparseable"
            r["results"] = {}
            return r
        r["type"] = "ec"
        r["x"] = _ub64toint(key["x"])
        r["y"] = _ub64toint(key["x"])
        r["results"] = checkall(r["x"], checks=checks)
    elif key["kty"] == "OKP":
        if "x" not in key or key["x"] == "":
            r["type"] = "unparseable"
            r["results"] = {}
            return r
        r["type"] = "ec"
        r["x"] = _ub64toint(key["x"])
        # no y coordinate for ed25519/ed448
        r["results"] = checkall(r["x"], checks=checks)
    else:
        r["type"] = "unsupported"
        r["results"] = {}

    return r
