import unittest
import os

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestBlocklist(unittest.TestCase):

    @unittest.skipUnless(os.environ.get("RUNBLTESTS"), "Not running blocklist tests")
    def test_rsabl(self):
        with open(f"{TDPATH}rsa-debianweak.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertFalse(r["results"])

    @unittest.skipUnless(os.environ.get("RUNBLTESTS"), "Not running blocklist tests")
    def test_ecbl(self):
        with open(f"{TDPATH}ec-p256-rfc-example.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        with open(f"{TDPATH}ed25519-rfc-example.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        with open(f"{TDPATH}x448-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertFalse(r["results"])

    # Testing key in SSH DSA pubkey format.
    # Python cryptography plans to deprecate this format,
    # we will need to find a solution.
    @unittest.skipUnless(os.environ.get("RUNBLTESTS"), "Not running blocklist tests")
    def test_dsabl(self):
        with open(f"{TDPATH}dsa-sshpub-ietf-example.key") as f:
            key = f.read()
        r = badkeys.checksshpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])


if __name__ == "__main__":
    unittest.main()
