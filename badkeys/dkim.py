import base64
import sys

PUBPRE = "-----BEGIN PUBLIC KEY-----\n"
PUBPOST = "\n-----END PUBLIC KEY-----"
EDASN1 = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00"


def parsedkim(line):
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
        der = EDASN1 + base64.b64decode(dkim["p"])
        return PUBPRE + base64.b64encode(der).decode() + PUBPOST
    sys.stderr.write(f"WARNING: Unknown DKIM key type {dkim['k']}\n")
    return False
