import hashlib
import json
import lzma
import os
import pathlib
import sys
import urllib.request

from .utils import _warnmsg


def _dlxz(url, filename, exphash, cachedir, quiet):
    if not quiet:
        print(f"Downloading {filename}...")
    dldata = urllib.request.urlopen(url).read()
    dlunpacked = lzma.decompress(dldata)
    dlhash = hashlib.sha256(dlunpacked).hexdigest()
    if dlhash != exphash:
        sys.exit(f"ERROR: SHA256 hash of downloaded {filename} does not match")
    pathlib.Path(f"{cachedir}_{filename}.tmp").write_bytes(dlunpacked)
    os.replace(f"{cachedir}_{filename}.tmp", f"{cachedir}{filename}")


def update_bl(lookup=False, quiet=False):
    UPDATEURL = "https://update.badkeys.info/"
    BKFORMAT = 0

    cachedir = str(pathlib.Path.home()) + "/.cache/badkeys/"
    if not os.path.exists(cachedir):
        pathlib.Path(cachedir).mkdir(parents=True)

    jurl = f"{UPDATEURL}/v{BKFORMAT}/badkeysdata.json"
    bkdata = urllib.request.urlopen(jurl).read().decode()
    bkdata_old = ""
    if os.path.exists(f"{cachedir}badkeysdata.json"):
        with open(f"{cachedir}badkeysdata.json") as f:
            bkdata_old = f.read()

    data = json.loads(bkdata)
    if data["bkformat"] != BKFORMAT:
        sys.exit("ERROR: Wrong format")

    if bkdata == bkdata_old:
        if not quiet:
            print("No new data")
    else:
        if not quiet:
            print("Writing new badkeysdata.json...")
        with open(f"{cachedir}badkeysdata.json", "w") as f:
            f.write(bkdata)

    # starting with blocklist.dat
    oldbl_sha256 = ""
    if os.path.exists(f"{cachedir}blocklist.dat"):
        with open(f"{cachedir}blocklist.dat", "rb") as f:
            oldbl_sha256 = hashlib.sha256(f.read()).hexdigest()

    if oldbl_sha256 != data["blocklist_sha256"]:
        _dlxz(data["blocklist_url"], "blocklist.dat", data["blocklist_sha256"], cachedir, quiet)

    # starting with lookup.txt
    oldlu_sha256 = ""
    if os.path.exists(f"{cachedir}lookup.txt"):
        with open(f"{cachedir}lookup.txt", "rb") as f:
            oldlu_sha256 = hashlib.sha256(f.read()).hexdigest()
        if not lookup and (oldlu_sha256 != data["lookup_sha256"]):
            _warnmsg("Old lookup.txt file found.")
            _warnmsg("You may want to run --update-bl-and-urls")

    if lookup and (oldlu_sha256 != data["lookup_sha256"]):
        _dlxz(data["lookup_url"], "lookup.txt", data["lookup_sha256"], cachedir, quiet)
