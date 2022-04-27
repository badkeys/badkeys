import unittest
import os

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestRoca(unittest.TestCase):
    def test_roca(self):
        with open(f"{TDPATH}rsa-roca.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["roca"])
        self.assertTrue("roca" in r["results"])
        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["roca"])
        self.assertFalse(r["results"])


if __name__ == "__main__":
    unittest.main()
