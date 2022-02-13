import hashlib
from importlib.resources import open_binary

_block = False


def rsabl(n, e=0):
    global _block

    if not _block:
        with open_binary("badkeys.keydata", "rsabl.dat") as f:
            _block = f.read()

    bb = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

    s256trunc = hashlib.sha256(bb).digest()[:15]

    mlists = {1: 'kompromat',
              2: 'houseofkeys',
              3: 'debian-ssl',
              4: 'debian-ssh',
              5: 'keypair',
              6: 'misc'
              }

    fbegin = 0
    fend = (len(_block) // 16) - 1
    while fbegin <= fend:
        fmiddle = (fbegin + fend) // 2
        val = _block[fmiddle * 16:fmiddle * 16 + 15]
        if s256trunc == val:
            bl_id = int(_block[fmiddle * 16 + 15])
            return {"detected": True, "subtest": mlists[bl_id],
                    "debug": "Truncated Hash: %s" % s256trunc.hex()}
        if s256trunc > val:
            fbegin = fmiddle + 1
        else:
            fend = fmiddle - 1

    return False
