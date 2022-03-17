import hashlib
from importlib.resources import open_binary

_rsabl = False
_ecbl = False


def _checkbl(val, bl):
    # we accept input as bytes or int
    if isinstance(val, int):
        bb = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    else:
        bb = val

    s256trunc = hashlib.sha256(bb).digest()[:15]

    mlists = {1: 'kompromat',
              2: 'houseofkeys',
              3: 'debian-ssl',
              4: 'debian-ssh',
              5: 'keypair',
              6: 'misc'
              }

    fbegin = 0
    fend = (len(bl) // 16) - 1
    while fbegin <= fend:
        fmiddle = (fbegin + fend) // 2
        val = bl[fmiddle * 16:fmiddle * 16 + 15]
        if s256trunc == val:
            bl_id = int(bl[fmiddle * 16 + 15])
            return {"detected": True, "subtest": mlists[bl_id],
                    "debug": "Truncated Hash: %s" % s256trunc.hex()}
        if s256trunc > val:
            fbegin = fmiddle + 1
        else:
            fend = fmiddle - 1

    return False


def rsabl(n, e=0):
    global _rsabl

    if not _rsabl:
        with open_binary("badkeys.keydata", "rsabl.dat") as f:
            _rsabl = f.read()

    return _checkbl(n, _rsabl)


def ecbl(x, y=0):
    global _ecbl

    if not _ecbl:
        with open_binary("badkeys.keydata", "ecbl.dat") as f:
            _ecbl = f.read()

    return _checkbl(x, _ecbl)
