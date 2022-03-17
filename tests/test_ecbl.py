import unittest
import os

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestEcbl(unittest.TestCase):
    def test_ecbl(self):
        with open(f"{TDPATH}ec-p256-rfc-example.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["ecbl"])
        self.assertTrue("ecbl" in r["results"])
        with open(f"{TDPATH}ed25519-rfc-example.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["ecbl"])
        self.assertTrue("ecbl" in r["results"])
        with open(f"{TDPATH}x448-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["ecbl"])
        self.assertFalse(r["results"])


if __name__ == "__main__":
    unittest.main()
