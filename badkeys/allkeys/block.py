import hashlib
from importlib.resources import open_binary

_bldata = False


def blocklist(inval):
    global _bldata

    if not _bldata:
        with open_binary("badkeys.keydata", "blocklist.dat") as f:
            _bldata = f.read()

    inval_b = inval.to_bytes((inval.bit_length() + 7) // 8, byteorder='big')

    s256trunc = hashlib.sha256(inval_b).digest()[:15]

    mlists = {1: 'kompromat',
              2: 'houseofkeys',
              3: 'debian-ssl',
              4: 'debian-ssh',
              5: 'keypair',
              6: 'misc'
              }

    fbegin = 0
    fend = (len(_bldata) // 16) - 1
    while fbegin <= fend:
        fmiddle = (fbegin + fend) // 2
        val = _bldata[fmiddle * 16:fmiddle * 16 + 15]
        if s256trunc == val:
            bl_id = int(_bldata[fmiddle * 16 + 15])
            if bl_id in mlists:
                subtest = mlists[bl_id]
            else:
                subtest = f"id{bl_id}"
            return {"detected": True, "subtest": subtest,
                    "debug": "Truncated Hash: %s" % s256trunc.hex()}
        if s256trunc > val:
            fbegin = fmiddle + 1
        else:
            fend = fmiddle - 1

    return False
