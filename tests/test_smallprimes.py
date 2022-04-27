import unittest
import os

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestSmallprimes(unittest.TestCase):
    def test_smallprimes(self):
        with open(f"{TDPATH}rsa-smallfactors.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["smallfactors"])
        self.assertTrue("smallfactors" in r["results"])
        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["smallfactors"])
        self.assertFalse(r["results"])


if __name__ == "__main__":
    unittest.main()
