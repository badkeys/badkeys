import urllib.request
import os.path
import pathlib
import json
import lzma
import hashlib
import sys


def update_bl(lookup=False):
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
        print("No new data")
    else:
        print("Writing new badkeysdata.json...")
        with open(f"{cachedir}badkeysdata.json", "w") as f:
            f.write(bkdata)

    # starting with blocklist.dat
    oldbl_sha256 = ""
    if os.path.exists(f"{cachedir}blocklist.dat"):
        with open(f"{cachedir}blocklist.dat", "rb") as f:
            oldbl_sha256 = hashlib.sha256(f.read()).hexdigest()

    if oldbl_sha256 != data["blocklist_sha256"]:
        print("Downloading blocklist.dat...")
        xzblocklist = urllib.request.urlopen(data["blocklist_url"]).read()
        blocklist = lzma.decompress(xzblocklist)
        newbl_sha256 = hashlib.sha256(blocklist).hexdigest()
        if newbl_sha256 != data["blocklist_sha256"]:
            sys.exit("ERROR: SHA256 hash of downloaded blocklist.dat does not match")
        with open(f"{cachedir}blocklist.dat", "wb") as f:
            f.write(blocklist)

    # starting with lookup.txt
    oldlu_sha256 = ""
    if os.path.exists(f"{cachedir}lookup.txt"):
        with open(f"{cachedir}lookup.txt", "rb") as f:
            oldlu_sha256 = hashlib.sha256(f.read()).hexdigest()
        if not lookup and (oldlu_sha256 != data["lookup_sha256"]):
            print("WARNING: Old lookup.txt file found.")
            print("You may want to run --update-bl-and-urls")

    if lookup and (oldlu_sha256 != data["lookup_sha256"]):
        print("Downloading lookup.txt...")
        xzlookup = urllib.request.urlopen(data["lookup_url"]).read()
        lookup = lzma.decompress(xzlookup)
        newlu_sha256 = hashlib.sha256(lookup).hexdigest()
        if newlu_sha256 != data["lookup_sha256"]:
            sys.exit("ERROR: SHA256 hash of downloaded lookup.txt does not match")
        with open(f"{cachedir}lookup.txt", "wb") as f:
            f.write(lookup)
