import base64
import binascii

from .checks import checkall, checkrsa


def checkdnskey(rec, checks):
    o = rec.split(maxsplit=3)
    keytype = int(o[2])
    try:
        key = base64.b64decode(o[3].replace(" ", "").encode())
    except binascii.Error:
        return {"type": "unparseable", "results": {}}
    r = {}
    if keytype in {1, 5, 7, 8, 10}:  # RSA
        # RSA key format description in RFC 3110 Section 2
        if len(key) < 3:
            return {"type": "unparseable", "results": {}}
        if key[0] == 0:
            elen = int.from_bytes(key[1:3], byteorder="big")
        else:
            elen = key[0]

        if len(key) < elen + 1:
            return {"type": "unparseable", "results": {}}

        r["type"] = "rsa"
        r["e"] = int.from_bytes(key[1:1 + elen], byteorder="big")
        r["n"] = int.from_bytes(key[1 + elen:], byteorder="big")
        r["bits"] = r["n"].bit_length()
        r["results"] = checkrsa(r["n"], r["e"], checks=checks)
        return r
    if keytype == 13:  # ECDSAP256SHA256
        if len(key) != 64:
            return {"type": "unparseable", "results": {}}
        r["curve"] = "p256"
        r["x"] = int.from_bytes(key[0:32], byteorder="big")
    if keytype == 14:  # ECDSAP384SHA384
        if len(key) != 96:
            return {"type": "unparseable", "results": {}}
        r["curve"] = "p384"
        r["x"] = int.from_bytes(key[0:48], byteorder="big")
    if keytype == 15:  # ED25519
        if len(key) != 32:
            return {"type": "unparseable", "results": {}}
        r["curve"] = "ed25519"
        r["x"] = int.from_bytes(key, byteorder="big")
    if keytype == 16:  # ED448
        if len(key) != 57:
            return {"type": "unparseable", "results": {}}
        r["curve"] = "ed448"
        r["x"] = int.from_bytes(key, byteorder="big")
    if "x" in r:
        r["type"] = "ec"
        r["results"] = checkall(r["x"], checks=checks)
        return r
    return {"type": "unsupported", "results": {}}
