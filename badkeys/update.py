import hashlib
import json
import lzma
import os
import pathlib
import string
import sys
import urllib.request

from .utils import _cachedir, _warnmsg


def _dlxz(url, filename, exphash, quiet):
    if not quiet:
        print(f"Downloading {filename}...")
    dldata = urllib.request.urlopen(url).read()
    dlunpacked = lzma.decompress(dldata)
    dlhash = hashlib.sha256(dlunpacked).hexdigest()
    if dlhash != exphash:
        sys.exit(f"ERROR: SHA256 hash of downloaded {filename} does not match")
    tmpfile = os.path.join(_cachedir(), f"_{filename}.tmp")
    pathlib.Path(tmpfile).write_bytes(dlunpacked)
    os.replace(tmpfile, os.path.join(_cachedir(), filename))


def update_bl(lookup=False, quiet=False):
    UPDATEURL = "https://update.badkeys.info/"
    BKFORMAT = 0

    if not os.path.exists(_cachedir()):
        pathlib.Path(_cachedir()).mkdir(parents=True)

    jurl = f"{UPDATEURL}/v{BKFORMAT}/badkeysdata.json"
    bkdata = urllib.request.urlopen(jurl).read()
    bkdata_old = ""
    bkjsonfile = os.path.join(_cachedir(), "badkeysdata.json")
    if os.path.exists(bkjsonfile):
        bkdata_old = pathlib.Path(bkjsonfile).read_bytes()

    data = json.loads(bkdata)
    if data["bkformat"] != BKFORMAT:
        sys.exit("ERROR: Wrong format")

    if "deprecated" in data:
        _warnmsg("Your badkeys version uses a deprecated blocklist format, please update!")
        # "deprecated" field can be 'true' or a string with additional info
        if isinstance(data["deprecated"], str):
            # make sure message is pure ASCII without ANSI control chars
            depmsg = "".join(filter(lambda x: x in string.printable, data["deprecated"]))
            _warnmsg(depmsg)

    if "blocklist_url" not in data:
        _warnmsg("Blocklist no longer available in requested format")
        return

    if bkdata == bkdata_old:
        if not quiet:
            print("No new data")
    else:
        if not quiet:
            print("Writing new badkeysdata.json...")
        pathlib.Path(bkjsonfile).write_bytes(bkdata)

    # starting with blocklist.dat
    oldbl_sha256 = ""
    if os.path.exists(os.path.join(_cachedir(), "blocklist.dat")):
        with open(os.path.join(_cachedir(), "blocklist.dat"), "rb") as f:
            oldbl_sha256 = hashlib.sha256(f.read()).hexdigest()

    if oldbl_sha256 != data["blocklist_sha256"]:
        _dlxz(data["blocklist_url"], "blocklist.dat", data["blocklist_sha256"], quiet)

    # starting with lookup.txt
    oldlu_sha256 = ""
    if os.path.exists(os.path.join(_cachedir(), "lookup.txt")):
        with open(os.path.join(_cachedir(), "lookup.txt"), "rb") as f:
            oldlu_sha256 = hashlib.sha256(f.read()).hexdigest()
        if not lookup and (oldlu_sha256 != data["lookup_sha256"]):
            _warnmsg("Old lookup.txt file found.")
            _warnmsg("You may want to run --update-bl-and-urls")

    if lookup and (oldlu_sha256 != data["lookup_sha256"]):
        _dlxz(data["lookup_url"], "lookup.txt", data["lookup_sha256"], quiet)
