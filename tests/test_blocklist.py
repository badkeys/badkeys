import os
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestBlocklist(unittest.TestCase):

    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_rsabl(self):
        with open(f"{TDPATH}rsa-debianweak.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["bits"] == 2048)
        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertFalse(r["results"])
        self.assertTrue(r["bits"] == 2048)

    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_ecbl(self):
        with open(f"{TDPATH}ec-p256-rfc-example.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["curve"] == "p256")
        with open(f"{TDPATH}ed25519-rfc-example.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["curve"] == "ed25519")
        with open(f"{TDPATH}x448-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["blocklist"])
        self.assertFalse(r["results"])
        self.assertTrue(r["curve"] == "x448")

    # Testing key in SSH DSA pubkey format.
    # Python cryptography plans to deprecate this format,
    # we will need to find a solution.
    @unittest.skipUnless(os.environ.get("RUN_ONLINETESTS"), "Skipping blocklist tests")
    def test_dsabl(self):
        with open(f"{TDPATH}dsa-sshpub-ietf-example.key") as f:
            key = f.read()
        r = badkeys.checksshpubkey(key, checks=["blocklist"])
        self.assertTrue("blocklist" in r["results"])
        self.assertTrue(r["bits"] == 1024)


if __name__ == "__main__":
    unittest.main()
