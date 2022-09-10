import hashlib
import mmap
import pathlib
import json
import sys

_blmeta = False
_bldata = False
_blextra = []


def _loadblmeta():
    global _blmeta
    mlist = {}
    cachedir = str(pathlib.Path.home()) + "/.cache/badkeys/"
    try:
        with open(f"{cachedir}badkeysdata.json") as f:
            jdata = json.loads(f.read())
    except FileNotFoundError:
        sys.exit("blocklist metadata not found, you need to run --update-bl")
    for bl in jdata["blocklists"]:
        blid = int(bl["id"])
        mlist[blid] = bl
    _blmeta = mlist


def _checkbl(bldata, s256trunc):
    fbegin = 0
    fend = (len(bldata) // 16) - 1
    while fbegin <= fend:
        fmiddle = (fbegin + fend) // 2
        val = bldata[fmiddle * 16 : fmiddle * 16 + 15]
        if s256trunc == val:
            bl_id = int(bldata[fmiddle * 16 + 15])
            if bl_id in _blmeta:
                subtest = _blmeta[bl_id]["name"]
            else:
                subtest = f"id{bl_id}"
            lhash = s256trunc[0:8].hex()
            return {
                "detected": True,
                "subtest": subtest,
                "blid": bl_id,
                "lookup": lhash,
                "debug": "Truncated Hash: %s" % s256trunc.hex(),
            }
        if s256trunc > val:
            fbegin = fmiddle + 1
        else:
            fend = fmiddle - 1

    return False


def blocklist(inval):
    global _blmeta, _bldata

    if not _blmeta:
        _loadblmeta()

    if not _bldata:
        cachedir = str(pathlib.Path.home()) + "/.cache/badkeys/"
        try:
            with open(f"{cachedir}blocklist.dat", "rb") as f:
                _bldata = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except FileNotFoundError:
            sys.exit("blocklist.dat not found, you need to run --update-bl")

    inval_b = inval.to_bytes((inval.bit_length() + 7) // 8, byteorder="big")

    s256trunc = hashlib.sha256(inval_b).digest()[:15]

    ret = _checkbl(_bldata, s256trunc)

    if not ret and _blextra != []:
        for bl in _blextra:
            ret = _checkbl(bl, s256trunc)

    return ret


def loadextrabl(fpath):
    with open(fpath, "rb") as f:
        _blextra.append(mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ))


def urllookup(blid, lhash, type="show"):
    global _blmeta
    try:
        from binary_file_search.BinaryFileSearch import BinaryFileSearch
    except ModuleNotFoundError:
        sys.stderr.write("ERROR: URL lookup failed, needs binary_file_search module\n")
        return False

    if not _blmeta:
        _loadblmeta()

    lfile = str(pathlib.Path.home()) + "/.cache/badkeys/lookup.txt"

    try:
        with BinaryFileSearch(lfile, sep=";", string_mode=True) as bfs:
            x = bfs.search(lhash)
    except FileNotFoundError:
        sys.stderr.write("ERROR: lookup.txt not found, run --update-bl-and-urls\n")
        return False
    except KeyError:
        sys.stderr.write("ERROR: URL lookup failed, not found\n")
        return False
    d = _blmeta[blid]
    showurl = f"https://github.com/{d['repo']}/blob/{d['path']}/{x[0][1]}"
    rawurl = f"https://raw.githubusercontent.com/{d['repo']}/{d['path']}/{x[0][1]}"
    if type == "show":
        return showurl
    if type == "raw":
        return rawurl
    if type == "both":
        return [showurl, rawurl]
