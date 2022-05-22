import hashlib
import mmap
import pathlib
import json

_blmeta = False
_bldata = False


def blocklist(inval):
    global _blmeta, _bldata

    cachedir = str(pathlib.Path.home()) + "/.cache/badkeys/"

    mlist = {}
    if not _blmeta:
        with open(f"{cachedir}badkeysdata.json") as f:
            jdata = json.loads(f.read())
        for bl in jdata["blocklists"]:
            blid = int(bl["id"])
            mlist[blid] = {"name": bl["name"]}
        _blmeta = mlist

    if not _bldata:
        cachedir = str(pathlib.Path.home()) + "/.cache/badkeys/"
        with open(f"{cachedir}blocklist.dat", "rb") as f:
            _bldata = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)

    inval_b = inval.to_bytes((inval.bit_length() + 7) // 8, byteorder="big")

    s256trunc = hashlib.sha256(inval_b).digest()[:15]

    fbegin = 0
    fend = (len(_bldata) // 16) - 1
    while fbegin <= fend:
        fmiddle = (fbegin + fend) // 2
        val = _bldata[fmiddle * 16 : fmiddle * 16 + 15]
        if s256trunc == val:
            bl_id = int(_bldata[fmiddle * 16 + 15])
            if bl_id in _blmeta:
                subtest = _blmeta[bl_id]["name"]
            else:
                subtest = f"id{bl_id}"
            return {
                "detected": True,
                "subtest": subtest,
                "debug": "Truncated Hash: %s" % s256trunc.hex(),
            }
        if s256trunc > val:
            fbegin = fmiddle + 1
        else:
            fend = fmiddle - 1

    return False
