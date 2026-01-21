import base64
import binascii

from .utils import _warnmsg

PUBPRE = "-----BEGIN PUBLIC KEY-----\n"
PUBPOST = "\n-----END PUBLIC KEY-----"
EDASN1 = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"


def parsedkim(line):

    # remove escaped quote characters, they can break our parser
    line = line.replace('\\"', "")

    if '"' in line:
        add = 0
        dk = ""
        for x in line.split('"'):
            add ^= 1
            if add == 0:
                dk += x
    else:
        dk = line

    dkim = {}
    for x in dk.split(";"):
        s = x.split("=", 1)
        if len(s) != 2:
            continue
        key = s[0].strip()
        value = s[1].strip()
        dkim[key] = value
    if "p" not in dkim:
        return False
    if dkim["p"] == "":
        return False
    if "k" not in dkim:
        dkim["k"] = "rsa"

    if dkim["k"] == "rsa":
        return PUBPRE + dkim["p"] + PUBPOST
    if dkim["k"] == "ed25519":
        try:
            rawed = base64.b64decode(dkim["p"].encode("ascii"))
        except (binascii.Error, UnicodeEncodeError):
            return False
        if len(rawed) != 32:
            return False
        der = EDASN1 + rawed
        return PUBPRE + base64.b64encode(der).decode() + PUBPOST
    _warnmsg("Unknown DKIM key type")
    return False
