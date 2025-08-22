import os
import unittest

import badkeys

TDPATH = f"{os.path.dirname(__file__)}/data/"


class TestRoca(unittest.TestCase):
    def test_roca(self):
        with open(f"{TDPATH}rsa-roca.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["roca"])
        self.assertTrue("roca" in r["results"])
        self.assertTrue(r["bits"] == 2048)
        with open(f"{TDPATH}rsa-ok.key") as f:
            key = f.read()
        r = badkeys.checkpubkey(key, checks=["roca"])
        self.assertFalse(r["results"])
        self.assertTrue(r["bits"] == 2048)


if __name__ == "__main__":
    unittest.main()
