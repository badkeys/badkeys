import os
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestSharedprimes(unittest.TestCase):
    def test_sharedprimes(self):
        with open(f"{TDPATH}rsa-sharedprimes.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["sharedprimes"])
        self.assertTrue("sharedprimes" in r["results"])
        self.assertTrue(r["bits"] == 2048)
        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["sharedprimes"])
        self.assertFalse(r["results"])
        self.assertTrue(r["bits"] == 2048)


if __name__ == "__main__":
    unittest.main()
